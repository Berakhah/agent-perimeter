from datetime import UTC, date, datetime

import pytest

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import CANARY_CONTENT, assert_authorised
from agent_perimeter.checks.active.path_traversal import (
    CHECK,
    DIFFERENTIAL_INBOUNDS,
    DIFFERENTIAL_OUTBOUNDS,
)
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
    def __init__(
        self, *, traversal_succeeds: bool = False, differential_signal: bool = False
    ) -> None:
        self.traversal_succeeds = traversal_succeeds
        self.differential_signal = differential_signal
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.calls.append({"method": method, "params": params})
        if method != "tools/call":
            return {}
        arguments = (params or {}).get("arguments")
        path = str(arguments.get("path", "")) if isinstance(arguments, dict) else ""
        if self.traversal_succeeds and ".." in path:
            return {"content": [{"type": "text", "text": CANARY_CONTENT}]}
        if self.differential_signal and ".." in path:
            return {"content": [{"type": "text", "text": "no such file or directory"}]}
        return {"content": [{"type": "text", "text": "not found"}], "isError": True}

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
                name="read_file",
                description="Read a file.",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            )
        ],
        scope=scope,
    )


def test_check_requires_authorisation() -> None:
    assert CHECK.requires_auth is True


def test_probe_refuses_without_a_scope_file() -> None:
    with pytest.raises(AuthorizationRequired):
        CHECK.run(_context(ProbeTransport(traversal_succeeds=True), scope=None))


def test_assert_authorised_names_the_check() -> None:
    context = _context(ProbeTransport(traversal_succeeds=False), scope=None)
    with pytest.raises(AuthorizationRequired, match="active.path_traversal"):
        assert_authorised(context, "active.path_traversal")


def test_reachable_traversal_is_reported() -> None:
    findings = CHECK.run(_context(ProbeTransport(traversal_succeeds=True)))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-22"
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].claim.derivation is Derivation.PROBE


def test_contained_server_is_clean() -> None:
    assert CHECK.run(_context(ProbeTransport(traversal_succeeds=False))) == []


def test_probe_never_targets_a_system_file() -> None:
    transport = ProbeTransport(traversal_succeeds=True)
    CHECK.run(_context(transport))
    for call in transport.calls:
        params = call["params"]
        assert isinstance(params, dict)
        arguments = params.get("arguments", {})
        path = str(arguments.get("path", "")) if isinstance(arguments, dict) else ""
        assert "passwd" not in path
        assert "shadow" not in path
        assert "id_rsa" not in path


def test_finding_reports_the_path_not_the_contents() -> None:
    finding = CHECK.run(_context(ProbeTransport(traversal_succeeds=True)))[0]
    assert "canary" in finding.evidence.excerpt.lower()
    assert CANARY_CONTENT not in finding.evidence.excerpt


def test_no_canary_and_uniform_errors_is_clean() -> None:
    """Neither mode fires when the server answers identically either way and
    no canary is planted -- the honest 'nothing observed' outcome."""
    assert CHECK.run(_context(ProbeTransport())) == []


def test_differential_response_is_reported_when_no_canary_is_available() -> None:
    findings = CHECK.run(_context(ProbeTransport(differential_signal=True)))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "differential" in findings[0].evidence.excerpt.lower()
    assert findings[0].claim.confidence is not None
    assert findings[0].claim.confidence < 1.0


def test_finding_records_which_mode_produced_it() -> None:
    canary_finding = CHECK.run(_context(ProbeTransport(traversal_succeeds=True)))[0]
    assert "canary_confirmed" in canary_finding.evidence.excerpt

    differential_finding = CHECK.run(_context(ProbeTransport(differential_signal=True)))[0]
    assert "differential_response" in differential_finding.evidence.excerpt


def test_canary_mode_is_tried_before_differential_mode() -> None:
    """When both signals are available, canary confirmation -- the stronger
    evidence -- wins; the finding is still CRITICAL, not downgraded."""
    finding = CHECK.run(
        _context(ProbeTransport(traversal_succeeds=True, differential_signal=True))
    )[0]
    assert finding.severity is Severity.CRITICAL


def test_differential_payloads_are_benign() -> None:
    for payload in (DIFFERENTIAL_INBOUNDS, DIFFERENTIAL_OUTBOUNDS):
        for forbidden in ("passwd", "shadow", "id_rsa"):
            assert forbidden not in payload
