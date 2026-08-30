import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.cli import app
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
    monkeypatch.setattr("agent_perimeter.cli.fingerprint", lambda transport: MODERN)
    monkeypatch.setattr(
        "agent_perimeter.cli._build_transport",
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
