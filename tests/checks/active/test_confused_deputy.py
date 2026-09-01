from datetime import UTC, date, datetime

import pytest

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import assert_authorised
from agent_perimeter.checks.active.confused_deputy import CHECK
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

DEPUTY = ToolRecord(
    name="fetch_and_save",
    description="Fetch a URL and save the result.",
    input_schema={
        "type": "object",
        "properties": {"url": {"type": "string"}, "path": {"type": "string"}},
    },
)
INNOCENT = ToolRecord(
    name="read_file",
    description="Read a file.",
    input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
)


class ProbeTransport:
    def __init__(self, *, both_fire: bool) -> None:
        self.both_fire = both_fire

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method != "tools/call":
            return {}
        text = "read ok and fetched ok" if self.both_fire else "permission denied"
        return {"content": [{"type": "text", "text": text}]}

    def close(self) -> None: ...


def _context(
    transport: ProbeTransport, *tools: ToolRecord, scope: ScopeFile | None = SCOPE
) -> ScanContext:
    return ScanContext(
        target=TARGET,
        transport=transport,
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-6 brief, same as task-3/21/22): Feature.STATELESS_META
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
        tools=list(tools),
        scope=scope,
    )


def test_confirmed_pair_is_reported_as_critical() -> None:
    findings = CHECK.run(_context(ProbeTransport(both_fire=True), DEPUTY))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cwe == "CWE-441"
    assert findings[0].claim.derivation is Derivation.PROBE


def test_unconfirmed_pair_produces_nothing_here() -> None:
    """The schema-derived policy finding still stands; this adds no confirmation."""
    assert CHECK.run(_context(ProbeTransport(both_fire=False), DEPUTY)) == []


def test_tool_without_the_precondition_is_not_probed() -> None:
    assert CHECK.run(_context(ProbeTransport(both_fire=True), INNOCENT)) == []


def test_check_requires_authorisation() -> None:
    assert CHECK.requires_auth is True


def test_finding_records_both_capabilities_in_evidence() -> None:
    finding = CHECK.run(_context(ProbeTransport(both_fire=True), DEPUTY))[0]
    assert "net_out" in finding.evidence.excerpt
    assert "fs_read" in finding.evidence.excerpt


def test_probe_refuses_without_a_scope_file() -> None:
    with pytest.raises(AuthorizationRequired):
        CHECK.run(_context(ProbeTransport(both_fire=True), DEPUTY, scope=None))


def test_assert_authorised_names_the_check() -> None:
    context = _context(ProbeTransport(both_fire=False), DEPUTY, scope=None)
    with pytest.raises(AuthorizationRequired, match="active.confused_deputy"):
        assert_authorised(context, "active.confused_deputy")
