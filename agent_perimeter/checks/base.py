from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding


@runtime_checkable
class Check(Protocol):
    """Every check declares the features it needs, never a revision string."""

    @property
    def id(self) -> str: ...
    @property
    def cwe(self) -> str: ...
    @property
    def taxonomy_refs(self) -> tuple[str, ...]: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def requires_auth(self) -> bool: ...
    @property
    def requires_model(self) -> bool: ...
    @property
    def requires_features(self) -> frozenset[Feature]: ...

    def run(self, context: ScanContext) -> list[Finding]: ...
