"""agent-perimeter — command line entry point.

Week 1 scope: connect, fingerprint, report the revision claimed and the
features observed, and refuse active mode without authorisation.

Task 9: the pipeline itself (build transport -> fingerprint -> enumerate
tools -> decide which checks apply -> run them) now lives in
`agent_perimeter.scan_runner.run_scan`, shared with the API. This module
keeps only what is genuinely CLI-only: flag parsing, --only/--sarif/--html,
and the operator-supplied extras (--repo/--config/--env-file/
--agent-transcript) that have no HTTP-request equivalent yet.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.registry import summarise_skips
from agent_perimeter.drift.render import for_terminal
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile
from agent_perimeter.model.snapshot import ToolSnapshot
from agent_perimeter.scan_runner import DEFAULT_DATABASE_URL, ScanMode, run_scan

DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"

# Transport construction and tool-ambiguity computation now belong entirely
# to scan_runner; nothing here calls either directly any more.
# tests/test_cli.py's stub_fingerprint fixture patches
# `agent_perimeter.scan_runner.build_transport`/`fingerprint`, and
# tests/checks/test_all_checks.py imports `compute_ambiguous_tools` from
# `agent_perimeter.scan_runner` (both updated alongside this refactor).

# The plain `Severity` StrEnum sorts alphabetically (critical, high, info, low,
# medium) — wrong order. This is the actual severity ranking (revision §2.7).
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _parse_env(pairs: list[str]) -> dict[str, str]:
    """Parse repeated `--env KEY=VALUE` options.

    Fails closed: a value with no `=` is rejected rather than silently
    dropped or guessed at.
    """
    env: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            typer.echo(f"--env value {pair!r} is not in KEY=VALUE form.")
            raise typer.Exit(code=2)
        key, _, value = pair.partition("=")
        env[key] = value
    return env


def _invocation_flags(
    *,
    mode: ScanMode,
    scope_file: Path | None,
    config: Path | None,
    env_file: Path | None,
    repo: Path | None,
) -> tuple[str, ...]:
    """The flags a finding's `reproduction` command has to replay.

    Only what the operator actually supplied — nothing is invented. Without
    these, every `secrets/*` finding's reproduction re-runs with no source
    file to scan and reports nothing, and `revision.header_body_mismatch`'s
    re-runs passively and reports NOT_AUTHORISED. Values are shell-quoted
    here because `reproduction()` joins them into one command string.
    """
    flags: list[str] = []
    if mode is not ScanMode.PASSIVE:
        flags += ["--mode", mode.value]
    for name, value in (
        ("--scope-file", scope_file),
        ("--config", config),
        ("--env-file", env_file),
        ("--repo", repo),
    ):
        if value is not None:
            flags += [name, shlex.quote(str(value))]
    return tuple(flags)


DRIFT_CHECK_ID = "drift.description_drift"


def _read_snapshot(path: Path, *, flag: str) -> ToolSnapshot:
    try:
        return ToolSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        typer.echo(
            f"Could not read {flag} snapshot {path}: {exc}. "
            "Pass a file written by `agent-perimeter scan --snapshot`."
        )
        raise typer.Exit(code=2) from None


app = typer.Typer(
    add_completion=False,
    help="MCP security posture scanner.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """MCP security posture scanner."""
    pass


@app.command()
def scan(
    target: Annotated[str, typer.Option(help="A URL, or a stdio command to launch.")],
    mode: Annotated[ScanMode, typer.Option(help="passive or active")] = ScanMode.PASSIVE,
    scope_file: Annotated[Path | None, typer.Option(help="Authorisation for active mode.")] = None,
    image: Annotated[
        str, typer.Option(help="Container image for stdio targets.")
    ] = "python:3.12-slim",
    env: Annotated[
        list[str],
        typer.Option(help="Environment variable KEY=VALUE for a stdio target, may be repeated."),
    ] = [],  # noqa: B006 -- read-only; typer needs a concrete default, never mutated
    only: Annotated[str | None, typer.Option(help="Run a single check by id.")] = None,
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF 2.1.0 here.")] = None,
    repo: Annotated[Path | None, typer.Option(help="Local repo for history scanning.")] = None,
    config: Annotated[
        Path | None, typer.Option(help="MCP client config to scan for secrets.")
    ] = None,
    env_file: Annotated[
        Path | None, typer.Option("--env-file", help="Env file to scan for secrets.")
    ] = None,
    html: Annotated[Path | None, typer.Option(help="Write the HTML report here.")] = None,
    agent_transcript: Annotated[
        Path | None, typer.Option(help="Agent transcript for injection claim B.")
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Snapshot from an earlier scan of this target to diff against."),
    ] = None,
    snapshot: Annotated[
        Path | None, typer.Option(help="Write this scan's tool snapshot here.")
    ] = None,
    fail_on_drift: Annotated[
        bool,
        typer.Option("--fail-on-drift", help="Exit 3 if any tool changed since --baseline."),
    ] = False,
) -> None:
    try:
        scope = ScopeFile.model_validate_json(scope_file.read_text()) if scope_file else None
    except (OSError, ValidationError) as exc:
        typer.echo(f"Could not read scope file: {exc}")
        raise typer.Exit(code=2) from None
    env_dict = _parse_env(env)

    baseline_snapshot = (
        _read_snapshot(baseline, flag="--baseline") if baseline is not None else None
    )

    # Validate --only before doing any real work (opening a transport,
    # launching a container) — a typo'd check id must fail loudly, not
    # silently select zero checks and print an indistinguishable-from-clean
    # "No findings" (--only is also what every finding's own `reproduction`
    # command uses, so a sceptic re-running one needs this to fail closed).
    from agent_perimeter.checks.all_checks import ALL_CHECKS, summarise_errors

    if only is not None:
        known_ids = {c.id for c in ALL_CHECKS}
        if only not in known_ids:
            typer.echo(
                f"--only {only!r} is not a registered check id. "
                f"Known ids: {', '.join(sorted(known_ids))}"
            )
            raise typer.Exit(code=2)
    selected = [c for c in ALL_CHECKS if only is None or c.id == only]

    # Revision 2.5: _config / _env are read by secrets/* but scan_runner has
    # no notion of a Path CLI flag -- these are built here, from the
    # operator-supplied paths, and layered onto the shared pipeline's own
    # `raw` dict via `extra_raw` (a stdio target's own launch environment
    # fallback stays inside scan_runner.run_scan, and extra_raw's `_env`
    # here overrides it, same precedence as before this was extracted).
    extra_raw: dict[str, dict[str, object]] = {}
    if repo is not None:
        extra_raw["_repo_path"] = {"path": str(repo)}
    if config is not None:
        extra_raw["_config"] = json.loads(config.read_text(encoding="utf-8"))
        extra_raw["_config_path"] = {"path": str(config)}
    if env_file is not None:
        parsed_env: dict[str, object] = {}
        for line in env_file.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                parsed_env[key] = value
        extra_raw["_env"] = parsed_env
        extra_raw["_env_path"] = {"path": str(env_file)}
    if agent_transcript is not None:
        extra_raw["_agent_transcript"] = json.loads(agent_transcript.read_text())

    inv_flags = _invocation_flags(
        mode=mode, scope_file=scope_file, config=config, env_file=env_file, repo=repo
    )

    try:
        outcome = run_scan(
            target,
            mode,
            scope,
            image=image,
            env=env_dict,
            checks=selected,
            extra_raw=extra_raw,
            invocation_flags=inv_flags,
            baseline=baseline_snapshot,
        )
    except AuthorizationRequired as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from None
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}")
        raise typer.Exit(code=2) from None

    result = outcome.fingerprint
    claimed = result.revision_claimed.value if result.revision_claimed else "unknown"
    observed = ", ".join(sorted(feature.value for feature in result.features)) or "none"
    typer.echo(f"Revision claimed:  {claimed}")
    typer.echo(f"Features observed: {observed}")

    baseline_ref = shlex.quote(str(baseline)) if baseline is not None else "<baseline.json>"
    current_ref = shlex.quote(str(snapshot)) if snapshot is not None else "<current.json>"
    findings = [
        f.model_copy(
            update={
                "reproduction": f.reproduction.replace("<baseline.json>", baseline_ref).replace(
                    "<current.json>", current_ref
                )
            }
        )
        if f.check_id == DRIFT_CHECK_ID
        else f
        for f in outcome.findings
    ]

    for finding in sorted(findings, key=lambda f: SEVERITY_RANK[f.severity]):
        typer.echo(for_terminal(f"[{finding.severity.value}] {finding.check_id}: {finding.title}"))

    summary = " ".join(
        part
        for part in (summarise_skips(outcome.skipped), summarise_errors(outcome.errored))
        if part
    )
    if not findings:
        typer.echo("No findings for the checks that ran. " + summary)
    else:
        typer.echo(f"{len(findings)} findings. " + summary)

    if snapshot is not None:
        snapshot.write_text(outcome.snapshot.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"Snapshot written to {snapshot}")
    if fail_on_drift and baseline is None:
        typer.echo(
            "--fail-on-drift had no effect: no --baseline was given, so "
            f"{DRIFT_CHECK_ID} was skipped."
        )

    if sarif is not None:
        from agent_perimeter.report.sarif import to_sarif

        workspace = sarif.parent if sarif.parent != Path("") else Path(".")
        sarif.write_text(
            json.dumps(
                to_sarif(
                    findings,
                    target=target,
                    tool_version="0.1.0",
                    fingerprint=result,
                    workspace=workspace,
                ),
                indent=2,
            )
        )
        typer.echo(f"SARIF written to {sarif}")

    if html is not None:
        from agent_perimeter.eval.score import CheckScore
        from agent_perimeter.report.html import render_report

        published: list[CheckScore] = []
        html.write_text(
            render_report(
                findings=findings,
                edges=outcome.edges,
                fingerprint=result,
                target=target,
                skipped=outcome.skipped,
                scores=published,
            ),
            encoding="utf-8",
        )
        typer.echo(f"Report written to {html}")

    if fail_on_drift and any(f.check_id == DRIFT_CHECK_ID for f in findings):
        typer.echo("drift gate tripped: at least one tool changed since the baseline (exit 3).")
        raise typer.Exit(code=3)


def _resolve_operand(value: str, *, database_url: str) -> ToolSnapshot:
    if not value.startswith("scan:"):
        return _read_snapshot(Path(value), flag="drift")
    scan_id = value.removeprefix("scan:")
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import Session

    from agent_perimeter.api.drift import snapshot_from_scan
    from agent_perimeter.db.models import Scan

    url = os.path.expandvars(database_url)
    try:
        shown = make_url(url).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 - a malformed URL is only ever the unexpanded one below
        shown = database_url
    try:
        with Session(create_engine(url)) as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                typer.echo(
                    f"{value} is not a scan on record at {shown}. "
                    "Check the id, or pass --database-url."
                )
                raise typer.Exit(code=2)
            return snapshot_from_scan(session, scan)
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - any DBAPI failure is a usage-level refusal here
        typer.echo(
            f"Could not resolve {value} from {shown}: {type(exc).__name__}. "
            "Pass --database-url for a reachable database."
        )
        raise typer.Exit(code=2) from None


@app.command()
def drift(
    baseline: Annotated[str, typer.Argument(help="Snapshot file, or scan:<id>.")],
    current: Annotated[str, typer.Argument(help="Snapshot file, or scan:<id>.")],
    tool: Annotated[str | None, typer.Option(help="Only this tool.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit events as JSON.")] = False,
    database_url: Annotated[
        str, typer.Option(help="Where scan:<id> operands are resolved from.")
    ] = DEFAULT_DATABASE_URL,
) -> None:
    """Diff two tool snapshots. No network; the reproduction every drift finding cites."""
    from datetime import UTC, datetime

    from agent_perimeter.drift.compare import compare, plain_name
    from agent_perimeter.drift.render import render_events

    before = _resolve_operand(baseline, database_url=database_url)
    after = _resolve_operand(current, database_url=database_url)
    try:
        events = compare(before, after, now=datetime.now(UTC))
    except ValueError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from None
    if tool is not None:
        events = [e for e in events if plain_name(e.tool_name) == tool]
    if json_output:
        typer.echo(json.dumps([json.loads(e.model_dump_json()) for e in events]))
    elif not events:
        typer.echo("No drift between the two snapshots.")
    else:
        for line in render_events(events):
            typer.echo(line)
    if events:
        raise typer.Exit(code=3)


@app.command()
def census(
    endpoint: Annotated[str, typer.Option(help="Registry API base URL.")] = DEFAULT_REGISTRY,
    tier2_n: Annotated[int, typer.Option(help="Tier-2 packages per ecosystem.")] = 200,
    out: Annotated[Path, typer.Option(help="Directory for the report and raw data.")] = Path(
        "docs/census"
    ),
    database_url: Annotated[
        str,
        typer.Option(help="SQLAlchemy DSN. Defaults to this project's Postgres (see alembic.ini)."),
    ] = DEFAULT_DATABASE_URL,
    seed: Annotated[
        int | None,
        typer.Option(help="Tier-2 sample seed; generated and printed when omitted."),
    ] = None,
) -> None:
    """Collect a passive census of the public MCP registry.

    Reads the registry API and published package artifacts. Never connects to a
    third-party MCP server.
    """
    import httpx
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session

    from agent_perimeter.census.fetch import PaginationTruncated
    from agent_perimeter.census.run import run_census
    from agent_perimeter.db.models import Base, CensusRecord
    from agent_perimeter.report.census_report import export_raw, render_census

    out.mkdir(parents=True, exist_ok=True)

    # Every CensusRun/CensusRecord row this command writes lands in the same
    # Postgres alembic/docker-compose.yml already stand up - not a throwaway
    # file invisible to alembic, psql or a future API. --database-url exists
    # so a different deployment (or a test) can point elsewhere.
    engine = create_engine(os.path.expandvars(database_url))
    Base.metadata.create_all(engine)

    # Progress goes to stderr so stdout stays the parseable summary; the
    # timeout bounds every registry page and artifact download individually.
    with httpx.Client(timeout=30.0) as client, Session(engine) as session:
        try:
            run = run_census(
                session,
                client,
                endpoint=endpoint,
                tier2_n=tier2_n,
                seed=seed,
                progress=lambda m: typer.echo(m, err=True),
            )
        except PaginationTruncated as exc:
            # run_census never committed - the session's exit rolls its
            # CensusRun row back - so "Nothing written" is literally true
            # for the database as well as for --out.
            typer.echo(
                f"Census aborted: registry pagination failed at page {exc.page} after "
                f"{exc.entries_seen} entries - {exc.detail}. Nothing written.",
                err=True,
            )
            raise typer.Exit(code=1) from exc
        # Read while the session is still open - CensusRun's attributes are
        # expired by the commit inside run_census, and refreshing them after
        # the session closes below would raise DetachedInstanceError.
        typer.echo(f"Population size: {run.population_size}")
        typer.echo(f"Tier-2 n:        {run.tier2_n}")
        typer.echo(f"Sample seed:     {run.sample_seed}")
        # Printed unconditionally, zero included - B10: a number that only
        # shows up when it's bad is a number nobody trusts.
        typer.echo(f"Fetch failures:  {run.fetch_failures}")
        typer.echo(f"Method hash:     {run.method_hash}")

        # Same "read while the session is still open" constraint as the
        # summary lines above - records is a plain list by the time the
        # session closes, so render_census/export_raw need no session of
        # their own.
        records = list(
            session.execute(
                select(CensusRecord).where(CensusRecord.census_run_id == run.id)
            ).scalars()
        )
        html_path = out / "census.html"
        html_path.write_text(render_census(run, records), encoding="utf-8")
        # run.salt is the same salt run_census just used for every record's
        # coords_digest - passing it here (not a fresh one) is what makes
        # this export's digests verifiable against the database (final
        # review fix wave, Important #4/#5). Nullable only for a pre-release
        # row that predates this column (there are none); run_census always
        # sets it on the row it creates.
        if run.salt is None:
            raise RuntimeError("run_census did not persist a salt for this run")
        csv_path = export_raw(run, records, salt=run.salt, out=out)
        typer.echo(f"Report written to {html_path}")
        typer.echo(f"Raw data written to {csv_path}")
