"""Tools that interfere with other tools.

Two failure modes. A description naming another tool and instructing the model
how to treat it is cross-origin escalation: one server rewrites the agent's
behaviour toward another server's tool. And two names that normalise to the
same string mean a reviewer approving one has silently approved the other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

SEPARATORS = re.compile(r"[_\-\s.]+")


def normalised(name: str) -> str:
    """Collapse separators and case so confusable names compare equal."""
    return SEPARATORS.sub("", name).lower()


# Revision row 2: a bare mention of another tool's name is ordinary
# documentation ("use list_files first") and single-word names (get, read)
# match inside routine prose — only an imperative *directed at* the other
# tool is the cross-origin-escalation shape.
IMPERATIVE_TOWARD_OTHER = (
    r"before\s+(?:calling|using)",
    r"instead\s+of",
    r"never\s+(?:use|call)",
    r"you\s+must\s+(?:call|use)",
    r"do\s+not\s+(?:call|use)",
)


def _cross_reference_pattern(names: list[str]) -> re.Pattern[str] | None:
    """One compiled pattern for the whole scan — revision 7.4's O(n) fix.

    A single alternation of every tool name, gated behind imperative
    phrasing, compiled once and scanned once per description — not
    re.escape + re.search per (tool, other-tool) pair.
    """
    unique = sorted(set(names), key=len, reverse=True)
    if not unique:
        return None
    alternation = "|".join(re.escape(name) for name in unique)
    imperatives = "|".join(IMPERATIVE_TOWARD_OTHER)
    return re.compile(
        rf"(?:{imperatives})\s+(?:the\s+)?[`'\"]?({alternation})[`'\"]?\b", re.IGNORECASE
    )


@dataclass(frozen=True)
class ShadowingCheck:
    id: str = "descriptions.shadowing"
    cwe: str = "CWE-441"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM01", "owasp-mcp:MCP09")
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        return self._collisions(context) + self._cross_references(context)

    def _collisions(self, context: ScanContext) -> list[Finding]:
        seen: dict[str, str] = {}
        findings: list[Finding] = []
        for tool in context.tools:
            key = normalised(tool.name)
            if key in seen and seen[key] != tool.name:
                findings.append(
                    self._finding(
                        context,
                        f"Tools {seen[key]!r} and {tool.name!r} normalise to the same name",
                        f"{seen[key]} vs {tool.name}",
                        "CWE-1007",
                        f"{seen[key]}~{tool.name}",
                        derivation=Derivation.NAME,
                    )
                )
            seen.setdefault(key, tool.name)
        return findings

    def _cross_references(self, context: ScanContext) -> list[Finding]:
        names = [tool.name for tool in context.tools]
        pattern = _cross_reference_pattern(names)
        if pattern is None:
            return []
        findings: list[Finding] = []
        for tool in context.tools:
            for match in pattern.finditer(tool.description):
                other = match.group(1)
                if other == tool.name:
                    continue  # a tool referring to itself is not cross-tool
                findings.append(
                    self._finding(
                        context,
                        (
                            f"Tool {tool.name!r} description gives an imperative "
                            f"instruction about another tool {other!r}"
                        ),
                        tool.description,
                        "CWE-441",
                        f"{tool.name}->{other}",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                    )
                )
        return findings

    def _finding(
        self,
        context: ScanContext,
        title: str,
        excerpt: str,
        cwe: str,
        value: str,
        *,
        severity: Severity | None = None,
        derivation: Derivation = Derivation.DESCRIPTION,
        confidence: float | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity or self.severity,
            title=title,
            cwe=cwe,
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


CHECK = ShadowingCheck()
