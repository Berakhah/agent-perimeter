"""An MCP target given to the scanner as a plaintext http:// URL.

Not a TLS posture audit — that would be an active probe against the resolved
endpoint (weak protocol versions, certificate validity, HSTS), out of scope
for the passive static/ family. This detects one narrow, honest fact: the
operator supplied a cleartext URL, over which bearer tokens travel readable
by anything on the path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


@dataclass(frozen=True)
class CleartextTargetCheck:
    id: str = "static.cleartext_target"
    cwe: str = "CWE-319"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP07", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        if not context.target.startswith("http://"):
            return []

        return [
            Finding(
                check_id=self.id,
                severity=self.severity,
                title="Target was supplied as a cleartext http:// URL",
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt=f"target: {context.target}"),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value=context.target,
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.PROBE,
                    observed_at=datetime.now(UTC),
                ),
            )
        ]


CHECK = CleartextTargetCheck()
