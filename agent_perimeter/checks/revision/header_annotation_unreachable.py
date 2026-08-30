"""x-mcp-header annotations not statically reachable by a pure properties chain.

Behind items, oneOf/anyOf/allOf/not, if/then/else, or a $ref, the annotation
makes the tool definition invalid per the specification, and it is also the
natural way to evade a scanner or a lax intermediary that only walks
properties. MEDIUM: this is a spec-conformance defect with an evasion angle,
not a confirmed live injection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision._header_annotations import find_header_annotations
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


@dataclass(frozen=True)
class HeaderAnnotationUnreachableCheck:
    id: str = "revision.header_annotation_unreachable"
    cwe: str = "CWE-664"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(
        default_factory=lambda: frozenset({Feature.PARAM_HEADERS})
    )

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            for annotation in find_header_annotations(tool.input_schema):
                if annotation.reachable:
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=self.severity,
                        title=(
                            f"Tool {tool.name!r} has an x-mcp-header annotation at "
                            f"{annotation.pointer} not reachable by a plain properties chain"
                        ),
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.EXCERPT,
                            excerpt=f"{annotation.pointer}: x-mcp-header={annotation.value!r}",
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=f"{tool.name}{annotation.pointer}",
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.SCHEMA,
                            observed_at=datetime.now(UTC),
                        ),
                        confidence=0.7,
                    )
                )
        return findings


CHECK = HeaderAnnotationUnreachableCheck()
