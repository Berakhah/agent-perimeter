from datetime import UTC, date, datetime

import pytest

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import CANARY_MARKER, assert_authorised
from agent_perimeter.checks.active.command_injection import CHECK, PAYLOADS
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Revision
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile
from agent_perimeter.transport.revision import Fingerprint

TARGET = "https://mcp.example.test/rpc"
SCOPE = ScopeFile(
    target=TARGET,
    authorising_party="Example Ltd",
    authorised_on=date(2026, 8, 30),
    attestation="I authorise active probing.",
)


class ProbeTransport:
    def __init__(self, *, shell_reachable: bool) -> None:
        self.shell_reachable = shell_reachable
        self.sent: list[str] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method != "tools/call":
            return {}
        arguments = (params or {}).get("arguments")
        value = str(arguments.get("command", "")) if isinstance(arguments, dict) else ""
        self.sent.append(value)
        if self.shell_reachable and CANARY_MARKER in value:
            return {"content": [{"type": "text", "text": f"ok\n{CANARY_MARKER}"}]}
        return {"content": [{"type": "text", "text": "invalid command"}]}

    def close(self) -> None: ...


def _context(transport: ProbeTransport, scope: ScopeFile | None = SCOPE) -> ScanContext:
    return ScanContext(
        target=TARGET,
        transport=transport,
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-3 brief, same as task-21/22): Feature.STATELESS_META
            # does not exist -- a version-implies-feature proxy this design
            # deliberately avoids (see agent_perimeter/model/feature.py). No
            # feature is needed for these tests, so the fixture asserts none.
            features=frozenset(),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        tools=[
            ToolRecord(
                name="run",
                description="Run a command.",
                input_schema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                },
            )
        ],
        scope=scope,
    )


def test_reachable_shell_is_reported() -> None:
    findings = CHECK.run(_context(ProbeTransport(shell_reachable=True)))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-78"
    assert findings[0].severity is Severity.CRITICAL


def test_sanitised_server_is_clean() -> None:
    assert CHECK.run(_context(ProbeTransport(shell_reachable=False))) == []


def test_every_payload_is_a_benign_echo() -> None:
    for payload in PAYLOADS:
        assert "echo" in payload
        for destructive in ("rm ", "curl", "wget", "nc ", ">", "dd ", "chmod"):
            assert destructive not in payload


def test_probe_stops_after_the_first_successful_payload() -> None:
    transport = ProbeTransport(shell_reachable=True)
    CHECK.run(_context(transport))
    assert len(transport.sent) == 1


def test_check_requires_authorisation() -> None:
    assert CHECK.requires_auth is True


def test_probe_refuses_without_a_scope_file() -> None:
    with pytest.raises(AuthorizationRequired):
        CHECK.run(_context(ProbeTransport(shell_reachable=True), scope=None))


def test_assert_authorised_names_the_check() -> None:
    context = _context(ProbeTransport(shell_reachable=False), scope=None)
    with pytest.raises(AuthorizationRequired, match="active.command_injection"):
        assert_authorised(context, "active.command_injection")
