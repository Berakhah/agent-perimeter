"""A publicly cacheable tool listing leaks one tenant's inventory to all of them.

2026-07-28 made cacheScope required on list results. "public" permits shared
intermediaries to cache the response; on an authenticated server that is an
information-disclosure primitive, not a performance setting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


@dataclass(frozen=True)
class CacheScopeCheck:
    id: str = "revision.cache_scope"
    cwe: str = "CWE-524"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM02", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(
        default_factory=lambda: frozenset({Feature.CACHEABLE_RESULT})
    )

    def run(self, context: ScanContext) -> list[Finding]:
        listing = context.raw.get("tools/list", {})
        if listing.get("cacheScope") != "public":
            return []

        # Evidence of authentication: a resolved OAuth metadata document, or a
        # recorded 401 + WWW-Authenticate from static.auth_mode's probe. Absent
        # both, "public" is the correct default for the unauthenticated
        # majority of the registry and is not a finding at MEDIUM.
        authenticated = bool(context.raw.get("oauth/metadata")) or bool(
            context.raw.get("_auth_probe", {}).get("www_authenticate")
        )
        severity = self.severity if authenticated else Severity.INFO
        title = (
            "Tool listing is marked publicly cacheable on an authenticated server"
            if authenticated
            else "Tool listing is marked publicly cacheable (no authentication evidence observed)"
        )

        excerpt = json.dumps(
            {k: listing[k] for k in ("cacheScope", "ttlMs") if k in listing}, indent=2
        )
        return [
            Finding(
                check_id=self.id,
                severity=severity,
                title=title,
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt=excerpt),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value="public",
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.SCHEMA,
                    observed_at=datetime.now(UTC),
                ),
                confidence=0.8 if authenticated else 0.5,
            )
        ]


CHECK = CacheScopeCheck()
