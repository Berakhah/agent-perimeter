"""The gap between the revision a server claims and the one it implements.

Only computable because the fingerprinter establishes claim and observation
independently. Default severity is INFO: a server mid-migration is not
vulnerable. A gap escalates only where it has a named security consequence,
and that name goes in the title.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import BUNDLES, Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

SECURITY_CONSEQUENCE: dict[Feature, tuple[Severity, str]] = {
    Feature.RESULT_TYPE: (
        Severity.MEDIUM,
        "clients cannot distinguish a complete result from an input_required one",
    ),
    Feature.SERVER_DISCOVER: (
        Severity.MEDIUM,
        "the mandatory discovery RPC is absent, so clients must guess capabilities",
    ),
    Feature.CACHEABLE_RESULT: (
        Severity.LOW,
        "cache lifetime and scope are unstated, so intermediaries decide for themselves",
    ),
}


@dataclass(frozen=True)
class ConformanceMismatchCheck:
    id: str = "revision.conformance_mismatch"
    cwe: str = "CWE-440"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.INFO
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        claimed = context.fingerprint.revision_claimed
        if claimed is None or claimed not in BUNDLES:
            return []

        missing = BUNDLES[claimed] - context.fingerprint.features
        findings: list[Finding] = []
        for feature in sorted(missing, key=lambda f: f.value):
            severity, consequence = SECURITY_CONSEQUENCE.get(
                feature, (Severity.INFO, "no security consequence identified")
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=severity,
                    title=(
                        f"Server claims {claimed.value} but does not implement "
                        f"{feature.value}: {consequence}"
                    ),
                    cwe=self.cwe,
                    taxonomy_refs=self.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.EXCERPT,
                        excerpt=(
                            f"claimed: {claimed.value}\n"
                            f"missing: {feature.value}\n"
                            f"observed: "
                            f"{', '.join(sorted(f.value for f in context.fingerprint.features))}"
                        ),
                    ),
                    reproduction=context.reproduction(self.id),
                    claim=Claim(
                        value=feature.value,
                        method=Method.DETERMINISTIC,
                        derivation=Derivation.PROBE,
                        observed_at=datetime.now(UTC),
                    ),
                )
            )
        return findings


CHECK = ConformanceMismatchCheck()
