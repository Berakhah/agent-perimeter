"""Local stand-ins for `bok-core` interfaces.

ponytail: `bok-core` is not published yet. These are concrete mirrors of the
contract, not permanent code. When the package ships, delete this module and
import from `bok_core` instead. Requirements raised on `bok-core` are recorded
in docs/superpowers/specs/2026-08-11-agent-perimeter-design.md section 8.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, model_validator


class Method(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL = "model"
    HUMAN = "human"
    DERIVED = "derived"


class Derivation(StrEnum):
    """bok-core requirement 1 — see spec section 8.

    All four are DETERMINISTIC methods with materially different
    trustworthiness, which is why derivation is tracked separately.
    """

    PROBE = "probe"
    SCHEMA = "schema"
    NAME = "name"  # a regex/pattern match over a tool or parameter identifier —
    # not a structural schema fact. Findings using it carry confidence < 1.0.
    DESCRIPTION = "description"
    ARTIFACT = "artifact"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    SYNTHETIC = "synthetic"
    REDACTED = "redacted"
    CLIENT_CONFIDENTIAL = "client_confidential"


class Claim(BaseModel):
    """A value that carries where it came from and how much to trust it."""

    model_config = ConfigDict(frozen=True)

    value: Any
    method: Method
    derivation: Derivation | None = None
    confidence: float | None = None
    observed_at: datetime
    parents: tuple[Claim, ...] = ()
    caveat: str | None = None

    @model_validator(mode="after")
    def _confidence_never_exceeds_parents(self) -> Self:
        if self.method is not Method.DERIVED or not self.parents:
            return self
        parent_confidences = [p.confidence for p in self.parents if p.confidence is not None]
        if not parent_confidences or self.confidence is None:
            return self
        if self.confidence > min(parent_confidences):
            msg = (
                f"DERIVED confidence {self.confidence} exceeds the minimum parent "
                f"confidence {min(parent_confidences)}"
            )
            raise ValueError(msg)
        return self

    def inherited_caveats(self) -> list[str]:
        """Every caveat in this claim's ancestry, nearest first."""
        found: list[str] = []
        for parent in self.parents:
            if parent.caveat is not None:
                found.append(parent.caveat)
            found.extend(parent.inherited_caveats())
        return found


Claim.model_rebuild()
