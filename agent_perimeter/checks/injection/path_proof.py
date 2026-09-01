"""Claim A: the injection path exists on this server.

A source tool returns content the scanner does not control — a fetched page, a
read file, a database row. A sink tool holds a privileged capability. If both
are exposed to the same agent context, an instruction embedded in the source's
output reaches the model alongside the sink's availability.

That is a fact about the tool set, not a prediction about a model, which is why
it is deterministic and counts toward the degraded-mode floor. Whether a given
agent actually takes the bait is claim B, and lives in agent_adapter.py.

The claim's derivation is the weakest derivation actually backing the path
(via DERIVATION_RANK, Task 2), not a hardcoded SCHEMA -- most edges build_graph
produces are NAME-derived (Task 1, revision §3, §7.4), and reporting SCHEMA
for those would overclaim exactly what Task 1 exists to stop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.graph.build import build_graph
from agent_perimeter.graph.policy import DERIVATION_RANK, capabilities_by_tool
from agent_perimeter.model.edge import Capability, CapabilityEdge
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

EXTERNAL_SOURCES = frozenset({Capability.NET_OUT, Capability.FS_READ, Capability.DB_READ})
PRIVILEGED_SINKS = frozenset(
    {Capability.EXEC, Capability.FS_WRITE, Capability.DB_WRITE, Capability.NET_OUT}
)


def find_paths(edges: list[CapabilityEdge]) -> list[tuple[str, str]]:
    """Return (source_tool, sink_tool) pairs sharing one agent context."""
    grouped = capabilities_by_tool(edges)
    sources = [t for t, caps in grouped.items() if caps & EXTERNAL_SOURCES]
    sinks = [t for t, caps in grouped.items() if caps & PRIVILEGED_SINKS]
    return [(s, k) for s in sources for k in sinks if s != k]


@dataclass(frozen=True)
class PathProofCheck:
    id: str = "injection.path_proof"
    cwe: str = "CWE-1427"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM01", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        edges = build_graph(context.tools)
        findings: list[Finding] = []

        for source, sink in find_paths(edges):
            source_edges = [e for e in edges if e.tool == source]
            sink_edges = [e for e in edges if e.tool == sink]
            # Report the weakest derivation actually backing this path, not a
            # hardcoded SCHEMA -- most edges build_graph produces are now
            # NAME-derived (Task 1), and claiming SCHEMA for those would be
            # exactly the overclaim Task 1 exists to fix.
            weakest = min(
                (e.derivation for e in source_edges + sink_edges),
                key=lambda d: DERIVATION_RANK[d],
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=self.severity,
                    title=(
                        f"An instruction embedded in content returned by {source!r} "
                        f"reaches the same context as privileged tool {sink!r}"
                    ),
                    cwe=self.cwe,
                    taxonomy_refs=self.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.EXCERPT,
                        excerpt=(
                            f"source {source}: "
                            f"{', '.join(e.capability.value for e in source_edges)}\n"
                            f"sink {sink}: "
                            f"{', '.join(e.capability.value for e in sink_edges)}\n"
                            f"Both are offered to the same agent context, so content "
                            f"from the source is in scope to influence the sink."
                        ),
                    ),
                    reproduction=context.reproduction(self.id),
                    claim=Claim(
                        value=f"{source}->{sink}",
                        method=Method.DERIVED,
                        derivation=weakest,
                        observed_at=datetime.now(UTC),
                        parents=tuple(e.claim for e in source_edges + sink_edges),
                        caveat=(
                            "Path proven from the tool set. Whether a given agent acts "
                            "on it is a property of that agent, measured separately."
                        ),
                    ),
                )
            )
        return findings


CHECK = PathProofCheck()
