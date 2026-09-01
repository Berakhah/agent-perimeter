"""Policy predicates over the capability graph.

The headline predicate is the confused-deputy precondition: a tool that can
both read local state and reach the network. Severity scales with the weakest
derivation in the pair, because a conclusion resting on two prose inferences is
weaker evidence than one resting on two probes — and saying so is the product.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.edge import Capability, CapabilityEdge
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

LOCAL_STATE = frozenset(
    {Capability.FS_READ, Capability.DB_READ, Capability.SECRET_READ, Capability.EXEC}
)

DERIVATION_SEVERITY: dict[Derivation, Severity] = {
    Derivation.PROBE: Severity.CRITICAL,
    Derivation.SCHEMA: Severity.HIGH,
    Derivation.ARTIFACT: Severity.HIGH,
    # NAME sits between SCHEMA and DESCRIPTION (Task 1, revision §3, §7.4): a
    # parameter-name match is real evidence, but not structure, so it scores
    # like a description-only pair rather than a schema-confirmed one.
    Derivation.NAME: Severity.MEDIUM,
    Derivation.DESCRIPTION: Severity.MEDIUM,
}

DERIVATION_RANK: dict[Derivation, int] = {
    Derivation.PROBE: 4,
    Derivation.SCHEMA: 3,
    Derivation.ARTIFACT: 3,
    Derivation.NAME: 2,
    Derivation.DESCRIPTION: 1,
}


@dataclass(frozen=True)
class Policy:
    id: str
    title: str
    cwe: str
    taxonomy_refs: tuple[str, ...]
    predicate: Callable[[set[Capability]], bool]


POLICIES: tuple[Policy, ...] = (
    Policy(
        id="policy.confused_deputy",
        title="can both read local state and reach the network",
        cwe="CWE-441",
        taxonomy_refs=("owasp-llm:LLM06", "mcp-spec:2026-07-28-security"),
        predicate=lambda caps: bool(caps & LOCAL_STATE) and Capability.NET_OUT in caps,
    ),
    Policy(
        id="policy.secret_egress",
        title="can read credentials and reach the network",
        cwe="CWE-200",
        taxonomy_refs=("owasp-llm:LLM02",),
        predicate=lambda caps: Capability.SECRET_READ in caps and Capability.NET_OUT in caps,
    ),
)


def capabilities_by_tool(edges: list[CapabilityEdge]) -> dict[str, set[Capability]]:
    grouped: dict[str, set[Capability]] = {}
    for edge in edges:
        grouped.setdefault(edge.tool, set()).add(edge.capability)
    return grouped


def _weakest(edges: list[CapabilityEdge], tool: str) -> Derivation:
    relevant = [e.derivation for e in edges if e.tool == tool]
    return min(relevant, key=lambda d: DERIVATION_RANK[d])


def evaluate(edges: list[CapabilityEdge], context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    for tool, capabilities in capabilities_by_tool(edges).items():
        for policy in POLICIES:
            if not policy.predicate(capabilities):
                continue
            weakest = _weakest(edges, tool)
            rationales = "\n".join(
                f"  {e.capability.value} <- {e.derivation.value}: {e.rationale}"
                for e in edges
                if e.tool == tool
            )
            note = (
                "inferred from description, not confirmed by probe"
                if weakest is Derivation.DESCRIPTION
                else f"weakest evidence: {weakest.value}"
            )
            findings.append(
                Finding(
                    check_id=policy.id,
                    severity=DERIVATION_SEVERITY[weakest],
                    title=f"Tool {tool!r} {policy.title}",
                    cwe=policy.cwe,
                    taxonomy_refs=policy.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.EXCERPT,
                        excerpt=f"{tool}:\n{rationales}\n({note})",
                    ),
                    reproduction=context.reproduction(policy.id),
                    claim=Claim(
                        value=tool,
                        method=Method.DERIVED,
                        derivation=weakest,
                        observed_at=datetime.now(UTC),
                        parents=tuple(e.claim for e in edges if e.tool == tool),
                        caveat=note,
                    ),
                )
            )
    return findings
