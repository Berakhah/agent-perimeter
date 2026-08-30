"""x-mcp-header annotations on a parameter typed number, or an unsafe integer.

The specification explicitly does not permit `number` on an annotated
parameter, and an integer outside the JS safe integer range (±2^53-1) cannot
round-trip through a JSON-consuming client without precision loss.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision._header_annotations import find_header_annotations
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

JS_SAFE_INTEGER = 2**53 - 1


def _type_violation(
    schema_type: object, tool_schema: dict[str, object], pointer: str
) -> str | None:
    if schema_type == "number":
        return "type is 'number', which the specification does not permit here"
    if schema_type == "integer":
        node: object = tool_schema
        for part in pointer.removeprefix("#/").split("/"):
            if part and isinstance(node, dict):
                node = node.get(part, {})
        bound = node.get("maximum") if isinstance(node, dict) else None
        if isinstance(bound, int | float) and abs(bound) > JS_SAFE_INTEGER:
            return f"declared maximum {bound} exceeds the JS safe integer range"
    return None


@dataclass(frozen=True)
class HeaderAnnotationTypeCheck:
    id: str = "revision.header_annotation_type"
    cwe: str = "CWE-1427"
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
                reason = _type_violation(
                    annotation.type_name, tool.input_schema, annotation.pointer
                )
                if reason is None:
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=self.severity,
                        title=f"Tool {tool.name!r} x-mcp-header at {annotation.pointer}: {reason}",
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.EXCERPT,
                            excerpt=f"{annotation.pointer}: type={annotation.type_name}",
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=f"{tool.name}{annotation.pointer}",
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.SCHEMA,
                            observed_at=datetime.now(UTC),
                        ),
                        confidence=0.85,
                    )
                )
        return findings


CHECK = HeaderAnnotationTypeCheck()
