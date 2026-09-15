"""The rug pull, caught: a tool that is not what it was at the last scan.

A point-in-time scan cannot see this. The runner compared this scan's
listing against a baseline snapshot of the same target and put the events
on the context; this check only groups and formats them (spec §6). It
never re-computes, so the API persists exactly what the report says.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import groupby

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.drift.compare import plain_name
from agent_perimeter.drift.render import SEVERITY_RANK, render_excerpt
from agent_perimeter.model.drift import DriftEvent
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


def _display_name(key: str) -> str:
    """`x#2` (compare.keyed_tools) renders as `'x' (duplicate 2)`."""
    name = plain_name(key)
    if name != key:
        return f"{name!r} (duplicate {key.rpartition('#')[2]})"
    return repr(key)


def _short(hash_value: str | None) -> str:
    return "(absent)" if hash_value is None else hash_value[:12]


@dataclass(frozen=True)
class DescriptionDriftCheck:
    id: str = "drift.description_drift"
    cwe: str = "CWE-494"
    taxonomy_refs: tuple[str, ...] = (
        "owasp-mcp:MCP03",
        "owasp-llm:LLM01",
        "mcp-spec:2026-07-28-security",
    )
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_baseline: bool = True
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        # Events arrive sorted by (tool_name, field) from compare(); groupby
        # relies on that.
        return [
            self._finding(context, key, list(group))
            for key, group in groupby(context.drift_events, key=lambda e: e.tool_name)
        ]

    def _finding(self, context: ScanContext, key: str, events: list[DriftEvent]) -> Finding:
        fields = ", ".join(e.field.value for e in events)
        severity = min((e.severity for e in events), key=lambda s: SEVERITY_RANK[s])
        value = "; ".join(
            f"{plain_name(key)} {e.field.value}:{_short(e.old_hash)}->{_short(e.new_hash)}"
            for e in events
        )
        baseline_ref = (
            f"scan:{context.baseline.scan_id}"
            if context.baseline is not None and context.baseline.scan_id
            else "<baseline.json>"
        )
        return Finding(
            check_id=self.id,
            severity=severity,
            title=f"Tool {_display_name(key)} changed since the baseline scan: {fields}",
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(
                kind=EvidenceKind.DIFF, excerpt="\n".join(render_excerpt(e) for e in events)
            ),
            reproduction=(
                f"agent-perimeter drift {baseline_ref} <current.json> --tool {plain_name(key)}"
            ),
            claim=Claim(
                value=value,
                method=Method.DETERMINISTIC,
                derivation=Derivation.DESCRIPTION,
                observed_at=events[0].detected_at,
            ),
            confidence=1.0,
        )


CHECK = DescriptionDriftCheck()
