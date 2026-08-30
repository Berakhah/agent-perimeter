# agent_perimeter/checks/descriptions/imperative_injection.py
"""Instructions addressed to the model, hiding in a field meant for the user.

A tool description is loaded into the model's planning context verbatim. Text
that instructs the model — rather than informing the user — is the tool
poisoning signature. Deterministic pattern matching, no model involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

# Revision 2026-08-29 section 3, row 3: the bare "you must/should/will" pattern
# is deleted outright — it matches ordinary user-facing prose ("You must
# provide a valid path") far more often than it matches a real directive, and
# there is no narrowing of it that keeps it useful. "always/never call this
# tool" stays; it has no benign reading.
IMPERATIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I)),
    ("override", re.compile(r"disregard\s+(all\s+)?(previous|prior|the\s+above)", re.I)),
    ("concealment", re.compile(r"do\s+not\s+(tell|inform|mention|reveal|show)\s+the\s+user", re.I)),
    ("concealment", re.compile(r"without\s+(telling|informing|notifying)\s+the\s+user", re.I)),
    ("model_directive", re.compile(r"\b(always|never)\s+call\s+this\s+tool\b", re.I)),
    ("role_claim", re.compile(r"</?(system|assistant|user)>", re.I)),
    # `s?` outside the alternation so ordinary third-person-singular inflections
    # ("sends", "uploads") still match — it sits outside all three capturing
    # groups, so group(3) below is still the URL.
    (
        "exfiltration",
        re.compile(r"\b(send|post|upload|forward)s?\b.{0,40}\b(to|at)\s+(https?://\S+)", re.I),
    ),
)


def _same_origin(url: str, target: str) -> bool:
    try:
        return urlsplit(url).netloc.lower() == urlsplit(target).netloc.lower()
    except ValueError:
        return False


@dataclass(frozen=True)
class ImperativeInjectionCheck:
    id: str = "descriptions.imperative_injection"
    cwe: str = "CWE-1427"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM01", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            for category, pattern in IMPERATIVE_PATTERNS:
                match = pattern.search(tool.description)
                if match is None:
                    continue
                if category == "exfiltration" and _same_origin(match.group(3), context.target):
                    continue  # sending data back to the server's own origin is its job
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=self.severity,
                        title=(
                            f"Tool {tool.name!r} description contains a {category} "
                            f"instruction addressed to the model"
                        ),
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.EXCERPT,
                            excerpt=tool.description,
                            highlight=(match.start(), match.end()),
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=match.group(0),
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.DESCRIPTION,
                            observed_at=datetime.now(UTC),
                        ),
                    )
                )
                break
        return findings


CHECK = ImperativeInjectionCheck()
