"""MRTR requestState that is not integrity-protected.

Under Multi Round-Trip Requests the server hands the client a `requestState`
and the client echoes it back on retry. It is round-trip data under partial
attacker influence, so it must be integrity-protected, bound to the principal,
and expiring. A value that decodes to readable JSON with no signature segment
is none of those.

Opportunistic: inspects any input_required result already captured. It does not
provoke one, because provoking one is an active probe.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding


def _is_transparent(value: str) -> bool:
    """True when the value reveals structured content without a signature."""
    if value.count(".") >= 2:
        return False
    try:
        if isinstance(json.loads(value), dict):
            return True
    except (ValueError, TypeError):
        pass
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        return isinstance(json.loads(decoded), dict)
    except (ValueError, UnicodeDecodeError):
        return False


@dataclass(frozen=True)
class RequestStateBindingCheck:
    id: str = "revision.request_state_binding"
    cwe: str = "CWE-200"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-mrtr")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=lambda: frozenset({Feature.MRTR}))

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for method, result in context.raw.items():
            if result.get("resultType") != "input_required":
                continue
            state = result.get("requestState")
            if not isinstance(state, str) or not _is_transparent(state):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    severity=self.severity,
                    title=(
                        f"MRTR requestState from {method} is transparent: its "
                        f"structure is readable without a key"
                    ),
                    cwe=self.cwe,
                    taxonomy_refs=self.taxonomy_refs,
                    evidence=Evidence(
                        kind=EvidenceKind.EXCERPT,
                        excerpt=f"requestState (first 120 chars): {state[:120]}",
                    ),
                    reproduction=context.reproduction(self.id),
                    claim=Claim(
                        value=method,
                        method=Method.DETERMINISTIC,
                        derivation=Derivation.PROBE,
                        observed_at=datetime.now(UTC),
                    ),
                )
            )
        return findings


CHECK = RequestStateBindingCheck()
