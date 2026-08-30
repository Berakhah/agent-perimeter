"""Authority broader than the task needs.

Two signals. An authorization server advertising wildcard or administrative
scopes hands every client more authority than any single task requires. A tool
annotated readOnlyHint whose name says otherwise is misdeclaring its own blast
radius — and the specification says annotations are untrusted unless the server
is trusted, which is precisely what a scan is deciding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

WILDCARD_SCOPES = frozenset({"*", "all", "admin", "root", "full_access", "write:all"})
MUTATING_NAME = re.compile(
    r"^(delete|remove|drop|write|create|update|set|put|post|patch|exec|run|send)",
    re.IGNORECASE,
)
# Interim proxy for a write/exec CapabilityEdge until Week 3's capability
# graph exists. A name prefix alone false-positives on run_query, post_process
# — this requires the description to independently say the tool mutates
# something, not just that its name starts with a mutating-shaped word.
# `s?` covers the common third-person-singular inflection ("deletes") without
# attempting full verb conjugation.
MUTATING_VERB = re.compile(
    r"\b(delete|remove|write|create|update|modify|execute|send|upload|drop)s?\b", re.IGNORECASE
)


@dataclass(frozen=True)
class ScopeBreadthCheck:
    id: str = "static.scope_breadth"
    cwe: str = "CWE-250"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM06", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        return self._scope_findings(context) + self._annotation_findings(context)

    def _scope_findings(self, context: ScanContext) -> list[Finding]:
        metadata = context.raw.get("oauth/metadata", {})
        scopes = metadata.get("scopes_supported")
        if not isinstance(scopes, list):
            return []
        offending = [s for s in scopes if str(s).lower() in WILDCARD_SCOPES]
        if not offending:
            return []
        return [
            self._finding(
                context,
                f"Authorization server advertises broad scope(s): {', '.join(offending)}",
                f"scopes_supported: {scopes}",
                str(offending),
            )
        ]

    def _annotation_findings(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            if not tool.annotations.get("readOnlyHint"):
                continue
            if not MUTATING_NAME.match(tool.name):
                continue
            if not MUTATING_VERB.search(tool.description):
                continue  # name-shaped alone is not corroborated
            findings.append(
                self._finding(
                    context,
                    f"Tool {tool.name!r} declares readOnlyHint but its name and "
                    f"description both indicate mutation",
                    f"{tool.name}.annotations.readOnlyHint = true; "
                    f"description: {tool.description!r}",
                    tool.name,
                    derivation=Derivation.NAME,
                    confidence=0.7,
                )
            )
        return findings

    def _finding(
        self,
        context: ScanContext,
        title: str,
        excerpt: str,
        value: str,
        *,
        derivation: Derivation = Derivation.SCHEMA,
        confidence: float | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=self.severity,
            title=title,
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt=excerpt),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=value,
                method=Method.DETERMINISTIC,
                derivation=derivation,
                observed_at=datetime.now(UTC),
            ),
            confidence=confidence,
        )


CHECK = ScopeBreadthCheck()
