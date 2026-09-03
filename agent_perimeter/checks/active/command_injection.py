"""Probe whether a parameter reaches a shell.

The payload appends `echo <canary>` through three standard separators. echo
changes nothing, writes nothing and reads nothing. If the marker returns, the
parameter reaches a shell — which is the whole finding. Nothing is escalated
and the probe stops at the first confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import (
    CANARY_MARKER,
    assert_authorised,
    call_tool,
    response_text,
)
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

EXEC_PARAMS = frozenset({"command", "cmd", "script", "shell", "exec", "argv"})

PAYLOADS: tuple[str, ...] = (
    f"true; echo {CANARY_MARKER}",
    f"true && echo {CANARY_MARKER}",
    f"true | echo {CANARY_MARKER}",
)


@dataclass(frozen=True)
class CommandInjectionCheck:
    id: str = "active.command_injection"
    cwe: str = "CWE-78"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM06", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = True
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        assert_authorised(context, self.id)

        findings: list[Finding] = []
        for tool in context.tools:
            properties = tool.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            for name in properties:
                if str(name).lower() not in EXEC_PARAMS:
                    continue
                hit = self._probe(context, tool.name, str(name))
                if hit is not None:
                    findings.append(hit)
        return findings

    def _probe(self, context: ScanContext, tool: str, param: str) -> Finding | None:
        for payload in PAYLOADS:
            text = response_text(call_tool(context, tool, {param: payload}))
            if CANARY_MARKER not in text:
                continue
            return Finding(
                check_id=self.id,
                severity=self.severity,
                title=f"Tool {tool!r} parameter {param!r} reaches a shell",
                cwe=self.cwe,
                taxonomy_refs=self.taxonomy_refs,
                evidence=Evidence(
                    kind=EvidenceKind.TRANSCRIPT,
                    excerpt=(
                        f"tools/call {tool} {{{param!r}: {payload!r}}}\n"
                        f"canary marker returned in the response, so the parameter "
                        f"was interpreted by a shell"
                    ),
                ),
                reproduction=context.reproduction(self.id),
                claim=Claim(
                    value=f"{tool}.{param}",
                    method=Method.DETERMINISTIC,
                    derivation=Derivation.PROBE,
                    observed_at=datetime.now(UTC),
                ),
            )
        return None


CHECK = CommandInjectionCheck()
