"""Capability handles travelling through model context as plain tool arguments.

2026-07-28 removed protocol-level sessions; cross-call state now moves as
server-minted handles passed as ordinary tool arguments. Those arguments sit in
the model's context, visible to anything that can influence the model's input.
An unconstrained, unmarked handle parameter is a replayable capability
reference, not an implementation detail.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

HANDLE_NAME = re.compile(
    r"(session|state|continuation|job|task|cursor)[_-]?(handle|token|id|ref)",
    re.IGNORECASE,
)
# Standard, spec-defined identifiers this check must not fire on: the MCP
# pagination cursor and the Tasks-extension handle. Both match HANDLE_NAME's
# shape but are ordinary protocol fields, not the capability-leak pattern this
# check targets.
EXCLUDED_NAMES = re.compile(r"^(cursor|cursor_id|task_id|taskId)$", re.IGNORECASE)
# maxLength bounds a string's length; it says nothing about whether the value
# is opaque, so it was dropped from the opacity markers (revision 3, row 6).
OPAQUE_MARKERS = ("pattern", "format", "enum")


@dataclass(frozen=True)
class StateHandleExposureCheck:
    id: str = "revision.state_handle_exposure"
    cwe: str = "CWE-200"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM02", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            properties = tool.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            for name, schema in properties.items():
                if not HANDLE_NAME.search(str(name)) or EXCLUDED_NAMES.match(str(name)):
                    continue
                if not isinstance(schema, dict):
                    continue
                if any(marker in schema for marker in OPAQUE_MARKERS):
                    continue
                findings.append(self._finding(context, tool.name, str(name), schema))
        return findings

    def _finding(
        self,
        context: ScanContext,
        tool: str,
        param: str,
        schema: dict[str, object],
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=self.severity,
            title=(
                f"Tool {tool!r} accepts unconstrained state handle {param!r}, "
                f"which travels through model context"
            ),
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(
                kind=EvidenceKind.EXCERPT, excerpt=json.dumps({param: schema}, indent=2)
            ),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=f"{tool}.{param}",
                method=Method.DETERMINISTIC,
                derivation=Derivation.NAME,
                observed_at=datetime.now(UTC),
            ),
            confidence=0.7,
        )


CHECK = StateHandleExposureCheck()
