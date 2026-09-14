import json
import shlex
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy
from typer.testing import CliRunner

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.cli import DEFAULT_DATABASE_URL, app
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint

runner = CliRunner()

MODERN = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER, Feature.RESULT_TYPE}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime.now(UTC),
    ),
)


class _FakeTransport:
    """A no-op stand-in for the real transport these tests don't exercise.

    Task 25 made `scan` keep the transport open past fingerprinting: it now
    also runs the discovery loop (`transport.request("server/discover")` /
    `"tools/list"`), `enumerate_tools`, and every registered check against a
    live `ScanContext.transport`. These tests stub `fingerprint()` itself but
    previously left `_build_transport` untouched, so target
    "https://mcp.example.test/rpc" made a real (and now un-stubbed) network
    call and failed with a DNS `ConnectError`. This fake keeps them hermetic.
    """

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


@pytest.fixture
def stub_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    # Task 9 moved the pipeline (fingerprint()/build_transport()) out of
    # cli.py and into scan_runner.py, shared with the API -- these patch the
    # names scan_runner.run_scan() actually calls now.
    monkeypatch.setattr("agent_perimeter.scan_runner.fingerprint", lambda transport: MODERN)
    monkeypatch.setattr(
        "agent_perimeter.scan_runner.build_transport",
        lambda target, image, env: _FakeTransport(),
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.revision.oauth_metadata.fetch_oauth_metadata",
        lambda target, **kwargs: None,
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.static.auth_probe.probe_auth_challenge",
        lambda target, **kwargs: {},
    )


def test_scan_reports_revision_and_features(stub_fingerprint: None) -> None:
    result = runner.invoke(app, ["scan", "--target", "https://mcp.example.test/rpc"])
    assert result.exit_code == 0
    assert "2026-07-28" in result.stdout
    assert "server_discover" in result.stdout


def test_html_option_writes_a_report(tmp_path: Path, stub_fingerprint: None) -> None:
    report = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", "--target", "https://mcp.example.test/rpc", "--html", str(report)],
    )
    assert result.exit_code == 0
    assert report.exists()
    assert "Agent Perimeter scan" in report.read_text(encoding="utf-8")


def test_active_mode_without_scope_file_refuses() -> None:
    result = runner.invoke(
        app, ["scan", "--target", "https://mcp.example.test/rpc", "--mode", "active"]
    )
    assert result.exit_code == 2
    assert "scope file" in result.stdout


def test_active_mode_with_scope_file_is_accepted(tmp_path: Path, stub_fingerprint: None) -> None:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "target": "https://mcp.example.test/rpc",
                "authorising_party": "Example Ltd",
                "authorised_on": "2026-08-30",
                "attestation": "I authorise active probing.",
            }
        )
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "https://mcp.example.test/rpc",
            "--mode",
            "active",
            "--scope-file",
            str(scope),
        ],
    )
    assert result.exit_code == 0


def test_active_mode_with_scope_file_for_a_different_target_is_rejected(
    tmp_path: Path, stub_fingerprint: None
) -> None:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "target": "https://someone-elses-server.test/rpc",
                "authorising_party": "Example Ltd",
                "authorised_on": "2026-08-30",
                "attestation": "I authorise active probing.",
            }
        )
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "https://mcp.example.test/rpc",
            "--mode",
            "active",
            "--scope-file",
            str(scope),
        ],
    )
    assert result.exit_code == 2
    assert "scope file target" in result.stdout


def test_empty_findings_copy_is_correct(stub_fingerprint: None) -> None:
    # --only pins this to a single check with a deterministic, empty result
    # (an https target is not a cleartext one) so the assertion is about the
    # copy, not about which of the 25 registered checks happen to fire
    # against the stubbed fingerprint/transport.
    result = runner.invoke(
        app,
        ["scan", "--target", "https://mcp.example.test/rpc", "--only", "static.cleartext_target"],
    )
    assert "No findings for the checks that ran" in result.stdout
    assert "You're secure" not in result.stdout


def test_llm_judge_is_skipped_as_model_unavailable(stub_fingerprint: None) -> None:
    # Review finding 1: no real model provider is wired anywhere in this
    # plan yet, so descriptions.llm_judge (the only requires_model check)
    # must be skipped, not silently run against the UnavailableJudge
    # placeholder and report a fabricated Method.MODEL finding.
    result = runner.invoke(app, ["scan", "--target", "https://mcp.example.test/rpc"])
    assert result.exit_code == 0
    assert "model_unavailable" in result.stdout
    assert "descriptions.llm_judge" not in result.stdout


def test_only_with_an_unknown_check_id_fails_closed() -> None:
    # Review finding 3: a typo'd --only must not silently select zero
    # checks and print a "No findings" indistinguishable from a real clean
    # scan — it must fail loudly, the same way an invalid scope file does.
    result = runner.invoke(
        app,
        ["scan", "--target", "https://mcp.example.test/rpc", "--only", "static.cleartext-target"],
    )
    assert result.exit_code == 2
    assert "not a registered check id" in result.stdout
    assert "static.cleartext_target" in result.stdout  # names a real, correct id


def test_reproduction_command_replays_the_config_flag_that_produced_it(
    tmp_path: Path, stub_fingerprint: None
) -> None:
    """`--only secrets.config_scan` with no `--config` finds nothing. The
    reproduction printed beside a finding has to be the command that
    actually produces it, and its SARIF uri has to be a URI reference, not
    an absolute host path."""
    config = tmp_path / "mcp.json"
    config.write_text(
        '{\n  "env": {\n    "API_KEY": "sk-test-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"\n  }\n}\n'
    )
    sarif = tmp_path / "out.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "https://mcp.example.test/rpc",
            "--only",
            "secrets.config_scan",
            "--config",
            str(config),
            "--sarif",
            str(sarif),
        ],
    )
    assert result.exit_code == 0, result.stdout
    document = json.loads(sarif.read_text())
    (emitted,) = document["runs"][0]["results"]
    assert f"--config {shlex.quote(str(config))}" in emitted["message"]["text"]
    assert "--only secrets.config_scan" in emitted["message"]["text"]
    uri = emitted["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "mcp.json", uri


def _stub_census_run(**overrides: object) -> SimpleNamespace:
    """Stand-in for census.run.CensusRun - every attribute the `census` CLI
    command reads, both to print its summary and (final-review fix wave,
    Important #4/#5) to render the report and raw export it now writes to
    `--out`. `id` is a real, matchable value so the command's own
    `CensusRecord` query runs against a real (if empty) session rather than
    crashing on a stub with no primary key."""
    fields: dict[str, object] = {
        "id": 1,
        "started_at": datetime(2026, 9, 1, tzinfo=UTC),
        "finished_at": datetime(2026, 9, 1, tzinfo=UTC),
        "population_size": 0,
        "tier2_n": 200,
        "sample_seed": 7,
        "fetch_failures": 0,
        "tool_version": "0.1.0",
        "method_hash": "deadbeef00000000",
        "registry_endpoint": "https://registry.modelcontextprotocol.io/v0/servers",
        "salt": b"test-salt-0000000000000000000000",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_census_defaults_to_the_project_postgres_not_sqlite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Finding 2 regression: `agent-perimeter census` must default to this
    project's real Postgres (the same DSN alembic.ini/migrations/env.py
    already use), not a throwaway SQLite file invisible to alembic, psql or
    a future API - and this has to prove the *wiring*, not just the constant,
    or a future edit could leave DEFAULT_DATABASE_URL correct while the
    command body still hardcodes something else.
    """
    assert DEFAULT_DATABASE_URL.startswith("postgresql+psycopg://")
    assert "sqlite" not in DEFAULT_DATABASE_URL

    captured_urls: list[str] = []
    real_create_engine = sqlalchemy.create_engine

    def fake_create_engine(url: str, *args: object, **kwargs: object) -> object:
        captured_urls.append(url)
        # cli.py's `from sqlalchemy import create_engine` is a lazy import
        # evaluated at call time, so patching the attribute it reads from is
        # enough. The engine actually returned is a real in-memory SQLite one
        # so the rest of the command (Base.metadata.create_all, Session)
        # still runs - this test is about which DSN reaches create_engine,
        # not about running the pipeline against a live Postgres.
        return real_create_engine("sqlite://")

    monkeypatch.setattr("sqlalchemy.create_engine", fake_create_engine)
    monkeypatch.setattr(
        "agent_perimeter.census.run.run_census",
        lambda session, client, **kwargs: _stub_census_run(),
    )

    result = runner.invoke(app, ["census", "--out", str(tmp_path / "out")])

    assert result.exit_code == 0, result.stdout
    assert captured_urls == [DEFAULT_DATABASE_URL]


def test_census_database_url_can_be_overridden_without_a_live_postgres(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--database-url` exists for exactly this: a deployment (or a test)
    that isn't the project's default Postgres. Verified end to end through
    the real `create_engine`/`Base.metadata.create_all` (no mocking of
    SQLAlchemy itself, unlike the default-DSN test above), so this also
    proves the override actually reaches the engine, not just the option
    parser.
    """
    monkeypatch.setattr(
        "agent_perimeter.census.run.run_census",
        lambda session, client, **kwargs: _stub_census_run(population_size=3),
    )
    db_path = tmp_path / "override.db"

    result = runner.invoke(
        app,
        [
            "census",
            "--out",
            str(tmp_path / "out"),
            "--database-url",
            f"sqlite:///{db_path}",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert db_path.exists()
    assert "Population size: 3" in result.stdout


def test_census_out_writes_the_html_report_and_raw_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Finding 4a: `census --out` created the directory and printed four
    summary lines, then did nothing else - `render_census`/`export_raw`
    (both pure functions with no CLI dependency) were never called, so the
    command could not produce the published census report end to end. The
    report is the actual deliverable of this command, not a byproduct of
    running it.
    """
    monkeypatch.setattr(
        "agent_perimeter.census.run.run_census",
        lambda session, client, **kwargs: _stub_census_run(),
    )
    out_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "census",
            "--out",
            str(out_dir),
            "--database-url",
            f"sqlite:///{tmp_path / 'census.db'}",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert (out_dir / "census.html").exists()
    assert (out_dir / "records.csv").exists()
    assert f"Report written to {out_dir / 'census.html'}" in result.stdout
    assert f"Raw data written to {out_dir / 'records.csv'}" in result.stdout


def test_census_exits_nonzero_and_writes_nothing_when_pagination_is_truncated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A registry page that fails after every retry used to end pagination
    silently and the run published the prefix as the population. The command
    must now say so, exit 1, and leave no report behind for anyone to mistake
    for a complete census."""
    from agent_perimeter.census.fetch import PaginationTruncated

    def boom(session: object, client: object, **kwargs: object) -> object:
        raise PaginationTruncated(3, 200, "page 3: status 502, gave up after 3 attempts")

    monkeypatch.setattr("agent_perimeter.census.run.run_census", boom)
    out_dir = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "census",
            "--out",
            str(out_dir),
            "--database-url",
            f"sqlite:///{tmp_path / 'census.db'}",
        ],
    )

    assert result.exit_code == 1, result.output
    assert not (out_dir / "census.html").exists()
    assert not (out_dir / "records.csv").exists()
    assert (
        "Census aborted: registry pagination failed at page 3 after 200 entries - "
        "page 3: status 502, gave up after 3 attempts. Nothing written."
    ) in result.output


def test_census_seed_flag_reaches_run_census_and_is_printed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`--seed` is what makes a published tier-2 sample reproducible: the
    value must reach run_census untouched and be echoed so the operator can
    record it. Also proves the CLI hands over a progress callback, so a long
    run is never a black box."""
    captured: dict[str, object] = {}

    def fake_run_census(session: object, client: object, **kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return _stub_census_run(sample_seed=kwargs["seed"])

    monkeypatch.setattr("agent_perimeter.census.run.run_census", fake_run_census)

    result = runner.invoke(
        app,
        [
            "census",
            "--seed",
            "5",
            "--out",
            str(tmp_path / "out"),
            "--database-url",
            f"sqlite:///{tmp_path / 'census.db'}",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["seed"] == 5
    assert callable(captured["progress"])
    assert "Sample seed:     5" in result.stdout


def test_census_client_has_a_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A registry or CDN request that hangs must not hang the census: the
    client the command builds carries a default timeout."""
    import httpx

    seen: list[httpx.Client] = []

    def fake_run_census(session: object, client: httpx.Client, **kwargs: object) -> SimpleNamespace:
        seen.append(client)
        return _stub_census_run()

    monkeypatch.setattr("agent_perimeter.census.run.run_census", fake_run_census)

    result = runner.invoke(
        app,
        [
            "census",
            "--out",
            str(tmp_path / "out"),
            "--database-url",
            f"sqlite:///{tmp_path / 'census.db'}",
        ],
    )

    assert result.exit_code == 0, result.output
    (client,) = seen
    assert client.timeout == httpx.Timeout(30.0)
