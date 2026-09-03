# agent_perimeter/checks/descriptions/name_schema_mismatch.py
"""A description promising capability the name and schema do not declare.

A tool called read_* whose description tells the model it also transmits data
is describing a different tool from the one it declares. The model plans from
the description; the reviewer approves the name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

READ_ONLY_NAME = re.compile(r"^(read|get|list|fetch|show|view|search|find)[_-]", re.I)
# `s?` outside the alternation for the same reason as imperative_injection's
# exfiltration pattern: "uploads"/"sends" are ordinary third-person-singular
# inflections that `\bupload\b` alone would not match.
MUTATING_VERB = re.compile(
    r"\b(upload|send|post|transmit|delete|remove|write|modify|execute|run)s?\b", re.I
)
# Revision row 5: the verb must take the tool's *own* object ("reads the file
# and uploads it") not an unrelated one ("... and logs analytics events").
# Cheap stand-in for real parsing: the tool's own object, derived from its
# name, or a pronoun referring back to it, must appear near the matched verb.
# Deliberately NOT a generic result-noun ("the result", "the data", "the
# contents") -- those describe *that* the tool produces output, not that the
# verb acts on the tool's own object, and false-positive on ordinary debug
# phrasing like "writes the result to stdout for debugging" (2026-08-29
# plan-revision audit).
OWN_OBJECT_MARKERS = ("it", "its", "them")
# A generic result-noun ("the data") near the verb is not itself evidence the
# verb acts on the tool's own object -- that's why it's deliberately absent
# from OWN_OBJECT_MARKERS above. But an explicit external-destination phrase
# is orthogonal evidence of exactly what this check exists to catch (a
# read-named tool that also sends its output out), regardless of what noun
# describes the payload -- "transmits the data to an external logging
# service" is not "writes the result to stdout for debugging" just because
# both use a generic noun.
EXTERNAL_DESTINATION = re.compile(
    r"\b(external|remote|third[- ]party|another\s+(?:service|server)|"
    r"a\s+different\s+(?:service|server|origin))\b",
    re.I,
)


def _own_object(name: str) -> str:
    stripped = READ_ONLY_NAME.sub("", name, count=1)
    return stripped.replace("_", " ").replace("-", " ").strip().lower()


def _verb_takes_own_object(description: str, match: re.Match[str], own_object: str) -> bool:
    # Word-boundary matching, not substring containment: naive `marker in
    # window` false-positives on words that merely contain a short marker as
    # a substring ("it" inside "audit", "file" inside "profile").
    window = description[match.end() : match.end() + 60].lower()
    if own_object and re.search(rf"\b{re.escape(own_object)}\b", window):
        return True
    if any(re.search(rf"\b{re.escape(marker)}\b", window) for marker in OWN_OBJECT_MARKERS):
        return True
    return bool(EXTERNAL_DESTINATION.search(window))


@dataclass(frozen=True)
class NameSchemaMismatchCheck:
    id: str = "descriptions.name_schema_mismatch"
    cwe: str = "CWE-440"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM06", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            if not READ_ONLY_NAME.match(tool.name):
                continue
            match = MUTATING_VERB.search(tool.description)
            if match is None:
                continue
            if not _verb_takes_own_object(tool.description, match, _own_object(tool.name)):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=self.severity,
                    title=(
                        f"Tool {tool.name!r} is named as read-only but its description "
                        f"claims it can {match.group(0).lower()}"
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
                        value=f"{tool.name}:{match.group(0).lower()}",
                        method=Method.DETERMINISTIC,
                        derivation=Derivation.DESCRIPTION,
                        observed_at=datetime.now(UTC),
                    ),
                )
            )
        return findings


CHECK = NameSchemaMismatchCheck()
