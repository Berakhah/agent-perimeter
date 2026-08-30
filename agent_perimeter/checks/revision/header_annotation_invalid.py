"""x-mcp-header annotations the client MUST reject.

The specification requires the annotation value to be a non-empty RFC 9110
token with no CR/LF or control characters, and to be case-insensitively
unique within the tool's inputSchema. A client that receives an invalid one
MUST reject the annotation and exclude the tool from tools/list — so a server
still advertising one is either non-conformant or testing what slips through
a lax client.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision._header_annotations import find_header_annotations
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

# RFC 9110 token: 1*tchar, tchar excludes control characters and delimiters.
TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _is_invalid(value: object) -> str | None:
    if not isinstance(value, str) or value == "":
        return "empty"
    if any(ord(c) < 0x20 or c in "\r\n" for c in value):
        return "contains CR/LF or a control character"
    if not TOKEN.match(value):
        return "is not an RFC 9110 token"
    return None


@dataclass(frozen=True)
class HeaderAnnotationInvalidCheck:
    id: str = "revision.header_annotation_invalid"
    cwe: str = "CWE-113"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(
        default_factory=lambda: frozenset({Feature.PARAM_HEADERS})
    )

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            annotations = find_header_annotations(tool.input_schema)
            seen: dict[str, str] = {}
            for annotation in annotations:
                reason = _is_invalid(annotation.value)
                if reason is not None:
                    findings.append(self._finding(context, tool.name, annotation.pointer, reason))
                    continue
                key = str(annotation.value).lower()
                if key in seen:
                    findings.append(
                        self._finding(
                            context,
                            tool.name,
                            annotation.pointer,
                            f"duplicates {seen[key]!r} case-insensitively",
                        )
                    )
                else:
                    seen[key] = str(annotation.value)
        return findings

    def _finding(self, context: ScanContext, tool: str, pointer: str, reason: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity=self.severity,
            title=f"Tool {tool!r} x-mcp-header at {pointer} is invalid: {reason}",
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt=f"{pointer}: {reason}"),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=f"{tool}{pointer}",
                method=Method.DETERMINISTIC,
                derivation=Derivation.SCHEMA,
                observed_at=datetime.now(UTC),
            ),
            confidence=0.9,
        )


CHECK = HeaderAnnotationInvalidCheck()
