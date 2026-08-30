"""What a check returns.

A finding without a citation and a reproduction is an opinion. Both are
required at construction, so an uncitable finding cannot be built.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from agent_perimeter._contracts import Claim, Severity
from agent_perimeter.checks.taxonomy import (
    UnknownCwe,
    UnknownTaxonomyRef,
    resolve,
    resolve_cwe,
)

CWE_PATTERN = re.compile(r"^CWE-\d+$")

# An excerpt is attacker-authored: four descriptions/* checks put a whole tool
# description in one, and it reaches the SARIF message and the on-disk scan
# profile verbatim. 2000 characters is comfortably more than any real
# credential fingerprint, transcript or schema fragment this tool emits, and
# small enough that a description inflated to megabytes cannot turn one
# finding into an unbounded GitHub alert body.
EXCERPT_MAX_CHARS = 2000
TRUNCATION_MARKER = "… [truncated]"

# Whitespace that renders as itself. Everything else non-printing —
# bidi overrides, zero-width joiners, Unicode tag characters, C0/C1 controls —
# is rendered as a codepoint label instead, the same convention
# `descriptions/unicode_anomaly.py` already uses (`f"U+{point:04X}"`), so the
# scanner's own report can never be display-manipulated (Trojan Source) by the
# content it is reporting on.
_RENDERABLE_WHITESPACE = frozenset("\n\r\t")


class EvidenceKind(StrEnum):
    TRANSCRIPT = "transcript"
    EXCERPT = "excerpt"
    SCREENSHOT = "screenshot"
    DIFF = "diff"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: EvidenceKind
    excerpt: str
    highlight: tuple[int, int] | None = None
    redacted: bool = False

    @field_validator("excerpt")
    @classmethod
    def _bounded_and_printable(cls, value: str) -> str:
        """Fixed here, not in the four checks that quote a tool description,
        so every current and future producer inherits it."""
        cleaned = "".join(
            char if char.isprintable() or char in _RENDERABLE_WHITESPACE else f"U+{ord(char):04X}"
            for char in value
        )
        if len(cleaned) > EXCERPT_MAX_CHARS:
            return cleaned[:EXCERPT_MAX_CHARS] + TRUNCATION_MARKER
        return cleaned


class FindingLocation(BaseModel):
    """A real file and line a finding traces to — never invented.

    Populated only when a check can point at genuine bytes on disk: a config
    file (`secrets/config_scan`, `secrets/env_scan`) or similar artifact.
    `None` means the finding has no such anchor, and Task 24's SARIF emitter
    anchors it to the scan-profile artifact it writes instead.
    """

    model_config = ConfigDict(frozen=True)

    uri: str
    line: int = 1


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str
    severity: Severity
    title: str
    cwe: str
    taxonomy_refs: tuple[str, ...]
    evidence: Evidence
    reproduction: str
    claim: Claim
    confidence: float | None = None
    location: FindingLocation | None = None

    @field_validator("cwe")
    @classmethod
    def _cwe_is_well_formed(cls, value: str) -> str:
        if not CWE_PATTERN.match(value):
            msg = f"cwe must look like CWE-nnn, got {value!r}"
            raise ValueError(msg)
        # A well-formed but unregistered CWE is still uncitable. The
        # check-level gate in tests only sees `Check.cwe`; several checks
        # construct findings carrying a *different*, per-finding CWE
        # (schema_composition's CWE-918, shadowing's CWE-1007), so the
        # invariant has to live where the value actually is.
        try:
            resolve_cwe(value)
        except UnknownCwe as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("taxonomy_refs")
    @classmethod
    def _at_least_one_taxonomy_ref(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            msg = "taxonomy_refs must contain at least one published entry"
            raise ValueError(msg)
        for ref in value:
            try:
                resolve(ref)
            except UnknownTaxonomyRef as exc:
                raise ValueError(str(exc)) from exc
        return value

    @field_validator("reproduction", "title", "check_id")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            msg = "reproduction, title and check_id must not be blank"
            raise ValueError(msg)
        return value
