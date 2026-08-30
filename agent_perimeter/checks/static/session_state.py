# agent_perimeter/checks/static/session_state.py
"""Session parameters surviving on a server that speaks the stateless revision.

2026-07-28 removed protocol-level sessions and Mcp-Session-Id. A server still
taking a session identifier as a tool parameter is carrying session state the
protocol no longer manages, so lifetime, binding and expiry are now entirely
its own responsibility — and usually unstated.

`Feature.SESSION_HEADER` is the legacy (pre-2026-07-28) protocol's own session
signal — present in the `2025-11-25` feature bundle, absent from
`2026-07-28`'s. A server that still shows it is legitimately speaking the
sessioned protocol, so a session-shaped parameter there is part of its actual
protocol design, not the redundant/leftover-state defect this check targets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

SESSION_NAME = re.compile(r"(mcp[_-]?session|session[_-]?(id|key))", re.IGNORECASE)


@dataclass(frozen=True)
class SessionStateCheck:
    id: str = "static.session_state"
    cwe: str = "CWE-613"
    taxonomy_refs: tuple[str, ...] = ("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")
    severity: Severity = Severity.MEDIUM
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        if Feature.SESSION_HEADER in context.fingerprint.features:
            return []
        findings: list[Finding] = []
        for tool in context.tools:
            properties = tool.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            for name in properties:
                if not SESSION_NAME.search(str(name)):
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=self.severity,
                        title=(
                            f"Tool {tool.name!r} takes session identifier {name!r} "
                            f"although the protocol no longer manages sessions"
                        ),
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.EXCERPT,
                            excerpt=f"{tool.name}.inputSchema.properties.{name}",
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=f"{tool.name}.{name}",
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.SCHEMA,
                            observed_at=datetime.now(UTC),
                        ),
                    )
                )
        return findings


CHECK = SessionStateCheck()
