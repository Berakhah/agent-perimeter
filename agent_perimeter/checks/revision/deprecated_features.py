"""Capabilities deprecated by 2026-07-28 that a server still advertises.

Roots, Sampling and Logging were deprecated by SEP-2577 under a twelve-month
removal window. Deprecation is a maintenance fact, not a vulnerability, so
severity stays low — except Sampling, which routes model calls back through
the client and therefore carries real blast radius.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

# Seeded from https://modelcontextprotocol.io/specification/2026-07-28/deprecated
# as of this revision's date (29 August 2026) — re-check against the live page
# rather than trusting this dict indefinitely. `side` says which capabilities
# object each key genuinely lives in: "server" (ServerCapabilities, observed
# from server/discover) or "client" (ClientCapabilities, observed only from
# the connecting operator's own config — a target's own advertisement was
# never the right place to look for a client-side fact).
DEPRECATED: dict[str, tuple[Severity, str, str]] = {
    "sampling": (
        Severity.MEDIUM,
        "Sampling is deprecated (twelve-month removal window) and routes model "
        "calls back through the client",
        "client",
    ),
    "roots": (
        Severity.LOW,
        "Roots is deprecated (twelve-month removal window); pass paths as tool parameters instead",
        "client",
    ),
    "logging": (
        Severity.LOW,
        "Logging is deprecated (twelve-month removal window); use stderr or OpenTelemetry",
        "server",
    ),
}


@dataclass(frozen=True)
class DeprecatedFeaturesCheck:
    id: str = "revision.deprecated_features"
    cwe: str = "CWE-477"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.LOW
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(
        default_factory=lambda: frozenset({Feature.SERVER_DISCOVER})
    )

    def run(self, context: ScanContext) -> list[Finding]:
        discover = context.raw.get("server/discover", {})
        server_capabilities = discover.get("capabilities")
        config = context.raw.get("_config", {})
        client_capabilities = config.get("capabilities") if isinstance(config, dict) else None

        findings: list[Finding] = []
        for name, (severity, title, side) in DEPRECATED.items():
            source = server_capabilities if side == "server" else client_capabilities
            if not isinstance(source, dict) or name not in source:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=severity,
                    title=title,
                    cwe=self.cwe,
                    taxonomy_refs=self.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.EXCERPT,
                        excerpt=f'capabilities contains "{name}"',
                    ),
                    reproduction=context.reproduction(self.id),
                    claim=Claim(
                        value=name,
                        method=Method.DETERMINISTIC,
                        derivation=Derivation.PROBE,
                        observed_at=datetime.now(UTC),
                    ),
                )
            )
        return findings


CHECK = DeprecatedFeaturesCheck()
