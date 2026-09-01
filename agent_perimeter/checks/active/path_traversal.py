"""Probe whether a path parameter escapes its intended root.

Two modes, tried in order; the finding records which one fired.

Canary mode reads a benign canary the fixture places at a known location and
reports that the path was reachable -- CRITICAL, because the marker coming
back is direct confirmation. It only works where the scanner itself planted
the canary: against a real target, with nothing at CANARY_PATH, this mode has
close to zero recall by construction (revision §8).

Differential-response mode is the fallback for a real target with no planted
canary. It sends two nonexistent filenames through the same parameter -- one
in-bounds, one shaped like a traversal -- and compares the server's error
text. A server that resolves ".." literally tends to surface a different
failure for the out-of-bounds path than for the in-bounds one; a server that
sandboxes path resolution centrally answers both the same way. This is
weaker evidence than a confirmed read -- HIGH, not CRITICAL, and
Derivation.PROBE with confidence < 1.0 -- because it shows the traversal
segments are treated differently, not that anything outside the root was
actually read.

Neither mode reads /etc/passwd, exfiltrates, or escalates. Reachability is
the finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import (
    CANARY_MARKER,
    CANARY_PATH,
    assert_authorised,
    call_tool,
    response_text,
)
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

PATH_PARAMS = frozenset({"path", "file", "filename", "filepath", "dir", "directory"})

DIFFERENTIAL_INBOUNDS = "agent-perimeter-missing-inbounds.txt"
DIFFERENTIAL_OUTBOUNDS = "../../../../../../agent-perimeter-missing-outbounds.txt"


class ProbeMode(StrEnum):
    CANARY_CONFIRMED = "canary_confirmed"
    DIFFERENTIAL_RESPONSE = "differential_response"


@dataclass(frozen=True)
class PathTraversalCheck:
    id: str = "active.path_traversal"
    cwe: str = "CWE-22"
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
                if str(name).lower() not in PATH_PARAMS:
                    continue
                finding = self._probe_canary(context, tool.name, str(name))
                if finding is None:
                    finding = self._probe_differential(context, tool.name, str(name))
                if finding is not None:
                    findings.append(finding)
        return findings

    def _probe_canary(self, context: ScanContext, tool: str, param: str) -> Finding | None:
        result = call_tool(context, tool, {param: CANARY_PATH})
        if CANARY_MARKER not in response_text(result):
            return None
        return Finding(
            check_id=self.id,
            severity=Severity.CRITICAL,
            title=(
                f"Tool {tool!r} parameter {param!r} escapes its root; "
                f"a canary outside the intended directory was read "
                f"(canary-confirmed)"
            ),
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(
                kind=EvidenceKind.TRANSCRIPT,
                excerpt=(
                    f"mode: {ProbeMode.CANARY_CONFIRMED.value}\n"
                    f"tools/call {tool} {{{param!r}: {CANARY_PATH!r}}}\n"
                    f"server returned the canary marker; contents "
                    f"intentionally not recorded"
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

    def _probe_differential(self, context: ScanContext, tool: str, param: str) -> Finding | None:
        """Only reached when canary mode found nothing -- against a real
        target, where this check has no canary of its own to confirm with
        (revision §8)."""
        inbound_text = response_text(call_tool(context, tool, {param: DIFFERENTIAL_INBOUNDS}))
        outbound_text = response_text(call_tool(context, tool, {param: DIFFERENTIAL_OUTBOUNDS}))
        if inbound_text.strip().lower() == outbound_text.strip().lower():
            return None
        return Finding(
            check_id=self.id,
            severity=Severity.HIGH,
            title=(
                f"Tool {tool!r} parameter {param!r} handles a traversal-shaped "
                f"path differently from an in-bounds path (differential-response)"
            ),
            cwe=self.cwe,
            taxonomy_refs=self.taxonomy_refs,
            confidence=0.6,
            evidence=Evidence(
                kind=EvidenceKind.TRANSCRIPT,
                excerpt=(
                    f"mode: {ProbeMode.DIFFERENTIAL_RESPONSE.value}\n"
                    f"in-bounds {{{param!r}: {DIFFERENTIAL_INBOUNDS!r}}} -> "
                    f"{inbound_text[:120]!r}\n"
                    f"traversal {{{param!r}: {DIFFERENTIAL_OUTBOUNDS!r}}} -> "
                    f"{outbound_text[:120]!r}\n"
                    f"No canary was planted to confirm a read; this shows the "
                    f"traversal segments are treated differently, not that "
                    f"anything outside the root was actually read."
                ),
            ),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=f"{tool}.{param}",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                confidence=0.6,
                observed_at=datetime.now(UTC),
                caveat=(
                    "Differential-response signal, not a confirmed read: no "
                    "canary was available to prove the traversal succeeded."
                ),
            ),
        )


CHECK = PathTraversalCheck()
