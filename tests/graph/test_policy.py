from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.graph.policy import evaluate
from agent_perimeter.model.edge import Capability, CapabilityEdge
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


CONTEXT = ScanContext(
    target="https://mcp.example.test/rpc",
    transport=NullTransport(),
    fingerprint=Fingerprint(
        revision_claimed=Revision.R2026_07_28,
        features=frozenset({Feature.SERVER_DISCOVER}),
        claim=Claim(
            value="2026-07-28",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    ),
)


def _edge(tool: str, capability: Capability, derivation: Derivation) -> CapabilityEdge:
    return CapabilityEdge(
        tool=tool,
        capability=capability,
        derivation=derivation,
        claim=Claim(
            value=f"{tool}:{capability.value}",
            method=Method.DETERMINISTIC,
            derivation=derivation,
            observed_at=datetime.now(UTC),
        ),
        rationale="test",
    )


def test_confused_deputy_precondition_is_reported() -> None:
    edges = [
        _edge("t", Capability.FS_READ, Derivation.SCHEMA),
        _edge("t", Capability.NET_OUT, Derivation.SCHEMA),
    ]
    findings = evaluate(edges, CONTEXT)
    assert any(f.cwe == "CWE-441" for f in findings)
    assert findings[0].severity is Severity.HIGH


def test_probe_confirmed_pair_is_critical() -> None:
    edges = [
        _edge("t", Capability.FS_READ, Derivation.PROBE),
        _edge("t", Capability.NET_OUT, Derivation.PROBE),
    ]
    assert evaluate(edges, CONTEXT)[0].severity is Severity.CRITICAL


def test_description_only_pair_is_downgraded_to_medium() -> None:
    edges = [
        _edge("t", Capability.FS_READ, Derivation.DESCRIPTION),
        _edge("t", Capability.NET_OUT, Derivation.DESCRIPTION),
    ]
    finding = evaluate(edges, CONTEXT)[0]
    assert finding.severity is Severity.MEDIUM
    assert "inferred from description" in finding.evidence.excerpt


def test_capabilities_on_different_tools_do_not_combine() -> None:
    edges = [
        _edge("a", Capability.FS_READ, Derivation.SCHEMA),
        _edge("b", Capability.NET_OUT, Derivation.SCHEMA),
    ]
    assert evaluate(edges, CONTEXT) == []


def test_exec_plus_net_out_is_also_reported() -> None:
    edges = [
        _edge("t", Capability.EXEC, Derivation.SCHEMA),
        _edge("t", Capability.NET_OUT, Derivation.SCHEMA),
    ]
    assert len(evaluate(edges, CONTEXT)) >= 1


def test_secret_read_plus_net_out_is_reported() -> None:
    edges = [
        _edge("t", Capability.SECRET_READ, Derivation.SCHEMA),
        _edge("t", Capability.NET_OUT, Derivation.SCHEMA),
    ]
    assert any(f.cwe == "CWE-200" for f in evaluate(edges, CONTEXT))


def test_derived_claim_keeps_its_parents() -> None:
    edges = [
        _edge("t", Capability.FS_READ, Derivation.SCHEMA),
        _edge("t", Capability.NET_OUT, Derivation.SCHEMA),
    ]
    finding = evaluate(edges, CONTEXT)[0]
    assert finding.claim.method is Method.DERIVED
    assert len(finding.claim.parents) == 2


def test_single_capability_is_not_a_finding() -> None:
    assert evaluate([_edge("t", Capability.FS_READ, Derivation.SCHEMA)], CONTEXT) == []


def test_name_only_pair_is_also_downgraded_to_medium() -> None:
    """Derivation.NAME (Task 1, revision §3, §7.4) sits between SCHEMA and
    DESCRIPTION: a pair derived purely from parameter-name matches is real
    evidence, but not schema structure, so it scores like a
    description-only pair, not a schema-confirmed one."""
    edges = [
        _edge("t", Capability.FS_READ, Derivation.NAME),
        _edge("t", Capability.NET_OUT, Derivation.NAME),
    ]
    assert evaluate(edges, CONTEXT)[0].severity is Severity.MEDIUM
