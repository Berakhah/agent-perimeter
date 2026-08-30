"""Authorization server that cannot support the mandated iss validation.

2026-07-28 requires clients to validate a present `iss` against the recorded
issuer before redeeming an authorization code (RFC 9207). A server that does
not advertise iss support cannot participate in that defence, leaving clients
exposed to mix-up attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

ISS_FLAG = "authorization_response_iss_parameter_supported"


@dataclass(frozen=True)
class IssuerValidationCheck:
    id: str = "revision.issuer_validation"
    cwe: str = "CWE-346"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP07", "rfc:9207", "mcp-spec:2026-07-28-authorization")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        metadata = context.raw.get("oauth/metadata")
        if not metadata:
            return []
        if metadata.get(ISS_FLAG):
            return []

        return [
            Finding(
                check_id=self.id,
                severity=self.severity,
                title=(
                    "Authorization server does not advertise RFC 9207 iss support, "
                    "so clients cannot perform the mandated issuer validation"
                ),
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(
                    kind=EvidenceKind.EXCERPT,
                    excerpt=f"{ISS_FLAG} absent from authorization server metadata",
                ),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value=False,
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.PROBE,
                    observed_at=datetime.now(UTC),
                ),
            )
        ]


CHECK = IssuerValidationCheck()
