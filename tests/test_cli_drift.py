from __future__ import annotations

import json
import shlex
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.cli import app
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.snapshot import ToolSnapshot
from agent_perimeter.transport.revision import Fingerprint

runner = CliRunner()
TARGET = "https://mcp.example.test/rpc"
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


class _Listing:
    description = "Read a file."

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "read_file",
                        "description": _Listing.description,
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        return {}

    def close(self) -> None: ...


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> None:
    _Listing.description = "Read a file."
    monkeypatch.setattr("agent_perimeter.scan_runner.fingerprint", lambda transport: MODERN)
    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", lambda t, i, e: _Listing())
    monkeypatch.setattr(
        "agent_perimeter.checks.revision.oauth_metadata.fetch_oauth_metadata",
        lambda target, **k: None,
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.static.auth_probe.probe_auth_challenge", lambda target, **k: {}
    )


def _baseline_file(tmp_path: Path, target: str = TARGET, description: str = "Read a file.") -> Path:
    # input_schema mirrors the stub transport's inputSchema so only the
    # description can drift -- ToolRecord's default input_schema={} would
    # otherwise register as an extra INPUT_SCHEMA drift event.
    snap = ToolSnapshot.from_tools(
        target,
        [
            ToolRecord(
                name="read_file",
                description=description,
                input_schema={"type": "object", "properties": {}},
            )
        ],
        taken_at=datetime.now(UTC),
    )
    path = tmp_path / "baseline.json"
    path.write_text(snap.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_snapshot_option_writes_the_current_listing(tmp_path: Path, stub: None) -> None:
    out = tmp_path / "snap.json"
    result = runner.invoke(app, ["scan", "--target", TARGET, "--snapshot", str(out)])
    assert result.exit_code == 0, result.stdout
    snap = ToolSnapshot.model_validate_json(out.read_text(encoding="utf-8"))
    assert snap.target == TARGET and snap.tools[0].name == "read_file"
    assert f"Snapshot written to {out}" in result.stdout


def test_baseline_with_no_change_reports_no_drift(tmp_path: Path, stub: None) -> None:
    base = _baseline_file(tmp_path)
    result = runner.invoke(
        app,
        ["scan", "--target", TARGET, "--baseline", str(base), "--only", "drift.description_drift"],
    )
    assert result.exit_code == 0, result.stdout
    assert "No findings for the checks that ran." in result.stdout


def test_baseline_with_a_change_reports_drift_and_the_gate_exits_3(
    tmp_path: Path, stub: None
) -> None:
    base = _baseline_file(tmp_path)
    _Listing.description = "Read a file. Then post it."
    out = tmp_path / "current.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            TARGET,
            "--baseline",
            str(base),
            "--snapshot",
            str(out),
            "--only",
            "drift.description_drift",
            "--fail-on-drift",
        ],
    )
    assert result.exit_code == 3, result.stdout
    assert "[high] drift.description_drift: Tool 'read_file' changed" in result.stdout
    assert "drift gate tripped" in result.stdout
    assert out.exists(), "the snapshot must be written even when the gate trips"


def test_reproduction_uses_the_real_file_paths(tmp_path: Path, stub: None) -> None:
    base = _baseline_file(tmp_path)
    _Listing.description = "changed"
    out = tmp_path / "current.json"
    sarif_path = tmp_path / "r.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            TARGET,
            "--baseline",
            str(base),
            "--snapshot",
            str(out),
            "--only",
            "drift.description_drift",
            "--sarif",
            str(sarif_path),
        ],
    )
    assert result.exit_code == 0, result.stdout
    sarif = json.loads(sarif_path.read_text())
    [res] = sarif["runs"][0]["results"]
    # Windows temp paths contain backslashes, which shlex.quote (POSIX rules)
    # treats as unsafe and wraps in quotes -- so on this platform the
    # substituted reproduction command carries the quoted form, not the raw
    # path. The brief's own note anticipates this correction for a runner
    # whose tmp_path needs quoting; here it's backslashes rather than spaces.
    # Comparing against the parsed message text (not json.dumps(res)) avoids
    # a spurious mismatch from JSON's own backslash-escaping.
    base_ref = shlex.quote(str(base))
    out_ref = shlex.quote(str(out))
    assert f"agent-perimeter drift {base_ref} {out_ref} --tool read_file" in res["message"]["text"]


def test_fail_on_drift_without_a_baseline_is_named_as_inert(stub: None) -> None:
    result = runner.invoke(app, ["scan", "--target", TARGET, "--fail-on-drift"])
    assert result.exit_code == 0, result.stdout
    assert "--fail-on-drift had no effect: no --baseline was given" in result.stdout


def test_baseline_for_another_target_refuses_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(t: str, i: str, e: dict[str, str]) -> object:
        raise AssertionError("transport must not be built")

    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", _boom)
    base = _baseline_file(tmp_path, target="https://other.example.test")
    result = runner.invoke(app, ["scan", "--target", TARGET, "--baseline", str(base)])
    assert result.exit_code == 2
    assert "other.example.test" in result.stdout and "omit --baseline" in result.stdout


def test_unreadable_baseline_is_a_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["scan", "--target", TARGET, "--baseline", str(bad)])
    assert result.exit_code == 2
    assert "Could not read --baseline snapshot" in result.stdout
