# agent_perimeter/graph/policy_checks.py
"""Wrap each policy predicate as a registry Check.

Previously `evaluate(edges, context)` was called directly from cli.py after
applicable() had already run, so a policy finding got no skip accounting, no
auth-gate enforcement, no citation-gate enforcement, and was invisible to
ALL_CHECKS (revision §4.4). Wrapping each Policy as a Check runs it through
the same registry as every other check instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.graph.build import build_graph
from agent_perimeter.graph.policy import POLICIES, Policy, evaluate
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding


@dataclass(frozen=True)
class PolicyCheck:
    """One Policy, run through build_graph + evaluate and filtered to its own
    findings. `severity` here is nominal -- the real, derivation-scaled
    severity is set per finding inside evaluate()."""

    policy: Policy
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    @property
    def id(self) -> str:
        return self.policy.id

    @property
    def cwe(self) -> str:
        return self.policy.cwe

    @property
    def taxonomy_refs(self) -> tuple[str, ...]:
        return self.policy.taxonomy_refs

    def run(self, context: ScanContext) -> list[Finding]:
        edges = build_graph(context.tools)
        return [f for f in evaluate(edges, context) if f.check_id == self.policy.id]


POLICY_CHECKS: tuple[PolicyCheck, ...] = tuple(PolicyCheck(policy=p) for p in POLICIES)
