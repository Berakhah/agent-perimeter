"""A server that honours the body when Mcp-Method disagrees with it.

2026-07-28 requires Mcp-Method and Mcp-Name on Streamable HTTP POSTs so
intermediaries can route without parsing bodies. If the origin honours the body
when the header disagrees, an attacker presents one method to the gateway and
executes another at the origin.

This sends a deliberately inconsistent request, which is a crafted payload, so
requires_auth is True and the registry gates it behind a scope file. The probe
proves reachability and stops — it calls no tool and changes no state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding
from agent_perimeter.transport.base import TransportError


@dataclass(frozen=True)
class HeaderBodyMismatchCheck:
    id: str = "revision.header_body_mismatch"
    cwe: str = "CWE-346"
    taxonomy_refs: tuple[str, ...] = ("mcp-spec:2026-07-28-changelog", "owasp-mcp:MCP09")
    severity: Severity = Severity.HIGH
    requires_auth: bool = True
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        try:
            context.transport.request(
                "tools/list",
                {"_ap_header_override": "tools/call"},
            )
        except TransportError:
            return []

        return [
            Finding(
                check_id=self.id,
                severity=self.severity,
                title=(
                    "Server honoured the request body when Mcp-Method disagreed "
                    "with it, allowing header-based routing to be bypassed"
                ),
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(
                    kind=EvidenceKind.TRANSCRIPT,
                    excerpt=(
                        "Mcp-Method: tools/list\n"
                        'body: {"method": "tools/call"}\n'
                        "server returned a result instead of HeaderMismatchError (-32020)"
                    ),
                ),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value="body_honoured",
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.PROBE,
                    observed_at=datetime.now(UTC),
                ),
            )
        ]


CHECK = HeaderBodyMismatchCheck()
