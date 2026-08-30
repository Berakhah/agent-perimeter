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

    SCHEMA = "schema"
    NAME = "name"  # a regex/pattern match over a tool or parameter identifier —
    # not a structural schema fact. Findings using it carry confidence < 1.0.
    DESCRIPTION = "description"
    PROBE = "probe"
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


class SecretFingerprint:
    """A secret recorded so it can be recognised but never recovered.

    bok-core requirement 2 — see spec section 8. The constructor takes the raw
    value, derives what is needed, and retains none of it. There is no attribute,
    repr or serialisation from which the original can be reconstructed.

    Hard constraint 3: the raw value never reaches the database, the logs, the
    SARIF, or a screenshot, and is never tested against a live service.
    """

    __slots__ = ("sha256", "entropy", "prefix", "last4", "location")

    def __init__(
        self, *, sha256: str, entropy: float, prefix: str, last4: str, location: str
    ) -> None:
        self.sha256 = sha256
        self.entropy = entropy
        self.prefix = prefix
        self.last4 = last4
        self.location = location

    @classmethod
    def of(cls, value: str, *, location: str) -> SecretFingerprint:
        import hashlib
        import math
        from collections import Counter

        counts = Counter(value)
        length = len(value)
        entropy = (
            -sum((n / length) * math.log2(n / length) for n in counts.values())
            if length
            else 0.0
        )

        return cls(
            sha256=hashlib.sha256(value.encode()).hexdigest(),
            entropy=entropy,
            prefix=value[:4],
            last4=value[-4:],
            location=location,
        )

    def __repr__(self) -> str:
        return (
            f"SecretFingerprint(sha256={self.sha256[:12]}…, "
            f"entropy={self.entropy:.2f}, location={self.location!r})"
        )
