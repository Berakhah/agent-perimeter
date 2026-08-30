from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_perimeter._contracts import Severity
from agent_perimeter.model.feature import Feature


@runtime_checkable
class Check(Protocol):
    """Every check declares the features it needs, never a revision string."""

    id: str
    cwe: str
    taxonomy_refs: tuple[str, ...]
    severity: Severity
    requires_auth: bool
    requires_model: bool
    requires_features: frozenset[Feature]

    def run(self, context: object) -> list[object]: ...
