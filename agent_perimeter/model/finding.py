"""What a check returns.

A finding without a citation and a reproduction is an opinion. Both are
required at construction, so an uncitable finding cannot be built.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from agent_perimeter._contracts import Claim, Severity

CWE_PATTERN = re.compile(r"^CWE-\d+$")


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
        return value

    @field_validator("taxonomy_refs")
    @classmethod
    def _at_least_one_taxonomy_ref(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            msg = "taxonomy_refs must contain at least one published entry"
            raise ValueError(msg)
        return value

    @field_validator("reproduction", "title", "check_id")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            msg = "reproduction, title and check_id must not be blank"
            raise ValueError(msg)
        return value
