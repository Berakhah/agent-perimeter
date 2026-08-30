"""Concealed content in tool metadata.

What a human reviewer sees in an approval dialog and what the model parses are
not the same string when bidi overrides, zero-width characters or Unicode tag
characters are present. Tag-block concealment has been demonstrated against
three independent MCP server implementations, so this is not theoretical.

Fully deterministic. No model is involved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

BIDI_OVERRIDES = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF})
TAG_CHARACTERS = frozenset(range(0xE0000, 0xE0080))

# UTS #39-style confusable skeleton, scoped to the small set of Cyrillic and
# Greek letters most commonly used to spoof a Latin tool-name identifier.
# ponytail: hand-picked common cases, not the full Unicode confusables.txt
# table (https://www.unicode.org/Public/security/latest/confusables.txt) —
# widen this if a real-world sample shows a case it misses.
CONFUSABLE_SKELETON: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "ԁ": "d",
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "υ": "u",
    "ν": "v",
}


def scan_text(text: str) -> list[tuple[str, int, str]]:
    """Return (category, offset, codepoint) for structural anomalies only.

    Bidi overrides, zero-width and tag characters — never legitimate in tool
    metadata regardless of language. Mixed-script content is deliberately not
    flagged here: a non-English description is not an anomaly. Confusable
    tool-name detection is separate — see `_confusable_name` — because it is
    scoped to identifiers, not free text.
    """
    findings: list[tuple[str, int, str]] = []
    for offset, char in enumerate(text):
        point = ord(char)
        label = f"U+{point:04X}"
        if point in BIDI_OVERRIDES:
            findings.append(("bidi_override", offset, label))
        elif point in ZERO_WIDTH:
            findings.append(("zero_width", offset, label))
        elif point in TAG_CHARACTERS:
            findings.append(("tag_character", offset, label))
    return findings


def _confusable_name(name: str) -> tuple[int, str] | None:
    """(offset, codepoint) of the first confusable char if `name` mixes
    ordinary Latin letters with a confusable lookalike — the actual
    tool-name-spoofing shape. A name in one consistent non-Latin script has
    nothing to be confused with and is not flagged."""
    has_latin = any(c.isascii() and c.isalpha() for c in name)
    if not has_latin:
        return None
    for offset, char in enumerate(name):
        if char in CONFUSABLE_SKELETON:
            return offset, f"U+{ord(char):04X}"
    return None


@dataclass(frozen=True)
class UnicodeAnomalyCheck:
    id: str = "descriptions.unicode_anomaly"
    cwe: str = "CWE-1007"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM01", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            for field_name, text in (("name", tool.name), ("description", tool.description)):
                for category, offset, codepoint in scan_text(text):
                    findings.append(
                        self._finding(
                            context,
                            tool.name,
                            field_name,
                            category,
                            offset,
                            codepoint,
                            derivation=(
                                Derivation.NAME if field_name == "name" else Derivation.DESCRIPTION
                            ),
                        )
                    )
            confusable = _confusable_name(tool.name)
            if confusable is not None:
                offset, codepoint = confusable
                findings.append(
                    self._finding(
                        context,
                        tool.name,
                        "name",
                        "confusable_name",
                        offset,
                        codepoint,
                        derivation=Derivation.NAME,
                    )
                )
        return findings

    def _finding(
        self,
        context: ScanContext,
        tool: str,
        field_name: str,
        category: str,
        offset: int,
        codepoint: str,
        *,
        derivation: Derivation,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=self.severity,
            title=(
                f"Tool {tool!r} {field_name} contains a {category.replace('_', ' ')} "
                f"character ({codepoint})"
            ),
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(
                kind=EvidenceKind.EXCERPT,
                excerpt=f"{field_name} offset {offset}: {codepoint} ({category})",
                highlight=(offset, offset + 1),
            ),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=codepoint,
                method=Method.DETERMINISTIC,
                derivation=derivation,
                observed_at=datetime.now(UTC),
            ),
        )


CHECK = UnicodeAnomalyCheck()
