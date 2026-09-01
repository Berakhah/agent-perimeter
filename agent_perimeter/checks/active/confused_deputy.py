"""Confirm a suspected confused deputy by driving the pair.

Task 2's policy flags tools whose schema suggests they can both read local
state and reach the network — a HIGH resting on inference. This probe drives
the actual pair and, on confirmation, reports PROBE-derived evidence at
CRITICAL.

Nobody can passively prove a tool is a confused deputy; you can only prove the
preconditions and then confirm them. Reporting inference and confirmation at
the same severity would be exactly the overclaim B9 warns about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import (
    CANARY_PATH,
    CANARY_URL,
    assert_authorised,
    call_tool,
    response_text,
)
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.graph.build import build_graph
from agent_perimeter.graph.policy import LOCAL_STATE, capabilities_by_tool
from agent_perimeter.model.edge import Capability
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

DENIED = ("permission denied", "not allowed", "forbidden", "refused")


@dataclass(frozen=True)
class ConfusedDeputyCheck:
    id: str = "active.confused_deputy"
    cwe: str = "CWE-441"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM06", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = True
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        assert_authorised(context, self.id)

        edges = build_graph(context.tools)
        findings: list[Finding] = []

        for tool, capabilities in capabilities_by_tool(edges).items():
            local = capabilities & LOCAL_STATE
            if not local or Capability.NET_OUT not in capabilities:
                continue

            text = response_text(
                call_tool(context, tool, {"path": CANARY_PATH, "url": CANARY_URL})
            ).lower()
            if any(marker in text for marker in DENIED):
                continue

            local_names = ", ".join(sorted(c.value for c in local))
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=self.severity,
                    title=(
                        f"Tool {tool!r} exercised both local access and outbound "
                        f"network in a single call"
                    ),
                    cwe=self.cwe,
                    taxonomy_refs=self.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.TRANSCRIPT,
                        excerpt=(
                            f"tools/call {tool} with a canary path and the discard-port "
                            f"URL was not refused.\n"
                            f"capabilities confirmed: {local_names}, net_out\n"
                            f"response: {text[:200]}"
                        ),
                    ),
                    reproduction=context.reproduction(self.id),
                    claim=Claim(
                        value=tool,
                        method=Method.DETERMINISTIC,
                        derivation=Derivation.PROBE,
                        observed_at=datetime.now(UTC),
                    ),
                )
            )
        return findings


CHECK = ConfusedDeputyCheck()
