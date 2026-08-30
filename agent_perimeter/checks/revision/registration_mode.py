"""OAuth Dynamic Client Registration without Client ID Metadata Document support.

2026-07-28 deprecated RFC 7591 DCR in favour of Client ID Metadata Documents.
DCR remains available for backwards compatibility, so this is a maintenance
finding, not a vulnerability — severity stays LOW.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


@dataclass(frozen=True)
class RegistrationModeCheck:
    id: str = "revision.registration_mode"
    cwe: str = "CWE-477"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP07", "mcp-spec:2026-07-28-authorization")
    severity: Severity = Severity.LOW
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        metadata = context.raw.get("oauth/metadata")
        if not metadata or "registration_endpoint" not in metadata:
            return []
        if metadata.get("client_id_metadata_document_supported"):
            return []

        return [
            Finding(
                check_id=self.id,
                severity=self.severity,
                title=(
                    "Authorization server offers deprecated Dynamic Client "
                    "Registration with no Client ID Metadata Document support"
                ),
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(
                    kind=EvidenceKind.EXCERPT,
                    excerpt=f"registration_endpoint: {metadata['registration_endpoint']}",
                ),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value="dcr_only",
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.PROBE,
                    observed_at=datetime.now(UTC),
                ),
            )
        ]


CHECK = RegistrationModeCheck()
