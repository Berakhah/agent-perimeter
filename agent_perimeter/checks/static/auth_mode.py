"""A reachable HTTP MCP server with no evidence of authentication.

Across 5,205 open-source MCP repositories Astrix found roughly 53% using
static long-lived credentials and only 8.5% using OAuth. This check separates
"no evidence of authentication" (a real finding) from "authenticated by
something other than OAuth" (not a finding) and "the probe never ran" (info,
not silently dropped).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


@dataclass(frozen=True)
class AuthModeCheck:
    id: str = "static.auth_mode"
    cwe: str = "CWE-306"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP07", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        if not context.target.startswith(("http://", "https://")):
            return []
        if context.raw.get("oauth/metadata"):
            return []  # oauth: resolved metadata is the strongest evidence

        probe = context.raw.get("_auth_probe")
        if not probe:
            return [
                self._finding(
                    context, "not_determined", Severity.INFO, "the auth probe did not run"
                )
            ]

        status = probe.get("status_code")
        challenge = str(probe.get("www_authenticate", ""))
        if status == 401 and challenge:
            return []  # non_oauth: a real challenge naming a scheme is authentication

        return [
            self._finding(
                context,
                "unauthenticated",
                self.severity,
                f"probe observed status_code={status}, WWW-Authenticate={challenge!r}",
            )
        ]

    def _finding(
        self, context: ScanContext, verdict: str, severity: Severity, evidence: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=(
                "Server auth mode not determined: probe did not run"
                if verdict == "not_determined"
                else "Server shows no evidence of authentication"
            ),
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt=evidence),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=verdict,
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        )


CHECK = AuthModeCheck()
