# agent_perimeter/checks/static/token_passthrough.py
"""Tools that accept a caller credential as a parameter.

The specification itself names token passthrough as a known weakness. A tool
taking a bearer token, API key or authorization header as an argument is
forwarding the caller's credential to a downstream service, which is the
confused-deputy precondition.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

CREDENTIAL_NAME = re.compile(
    r"(bearer|api[_-]?key|authorization|auth[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|secret|password|credential)",
    re.IGNORECASE,
)
# Interim proxy for the confused-deputy precondition ("somewhere to forward
# the credential to") until Week 3's capability graph derives a real net_out
# edge. ponytail: schema-name heuristic, replace with CapabilityEdge lookup
# once graph/edges.py exists.
OUTBOUND_NAME = re.compile(r"(url|endpoint|webhook|callback|target[_-]?uri)", re.IGNORECASE)


def _has_outbound_destination(properties: dict[str, object]) -> bool:
    for name, schema in properties.items():
        if OUTBOUND_NAME.search(str(name)):
            return True
        if isinstance(schema, dict) and schema.get("format") == "uri":
            return True
    return False


@dataclass(frozen=True)
class TokenPassthroughCheck:
    id: str = "static.token_passthrough"
    cwe: str = "CWE-522"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP01", "owasp-llm:LLM06")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            properties = tool.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            corroborated = _has_outbound_destination(properties)
            for name in properties:
                if not CREDENTIAL_NAME.search(str(name)):
                    continue
                severity = self.severity if corroborated else Severity.MEDIUM
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=severity,
                        title=(
                            f"Tool {tool.name!r} accepts credential-shaped parameter "
                            f"{name!r}"
                            + (
                                ", and the schema also has an outbound-shaped "
                                "parameter — the confused-deputy precondition"
                                if corroborated
                                else " (no corroborating outbound destination observed)"
                            )
                        ),
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.EXCERPT,
                            excerpt=f"{tool.name}.inputSchema.properties.{name}",
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=f"{tool.name}.{name}",
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.NAME,
                            observed_at=datetime.now(UTC),
                        ),
                        confidence=0.75 if corroborated else 0.5,
                    )
                )
        return findings


CHECK = TokenPassthroughCheck()
