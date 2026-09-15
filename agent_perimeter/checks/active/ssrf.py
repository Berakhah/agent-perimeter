"""Probe whether a URL parameter restricts its outbound destination.

The canary points at the discard port on loopback, which accepts nothing and
hosts nothing. Nothing is fetched either way.

This probe has no observation channel independent of the target's own error
text (revision §8): there is no out-of-band listener confirming a connection
actually happened, only a regex over what the server chose to say. That is
why the finding is `info`, not HIGH -- it reports an unconfirmed signal, not
a proven SSRF, and the finding text says so explicitly.

Cloud metadata addresses are deliberately never probed: reaching one on
someone else's infrastructure is an intrusion even under a scope file, and
this probe already establishes the same fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.base import (
    CANARY_URL,
    assert_authorised,
    call_tool,
    response_text,
)
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

URL_PARAMS = frozenset({"url", "uri", "endpoint", "host", "webhook", "callback"})

ATTEMPT_SIGNALS = re.compile(
    r"(connection\s+refused|timed?\s*out|econnrefused|unreachable|"
    r"failed\s+to\s+connect|127\.0\.0\.1)",
    re.IGNORECASE,
)
REFUSAL_SIGNALS = re.compile(
    r"(not\s+(in\s+the\s+)?allow(ed|list)|blocked|denied|forbidden|"
    r"disallowed|policy)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SsrfCheck:
    id: str = "active.ssrf"
    cwe: str = "CWE-918"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM06", "mcp-spec:2026-07-28-security")
    severity: Severity = Severity.INFO
    requires_auth: bool = True
    requires_model: bool = False
    requires_baseline: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        assert_authorised(context, self.id)

        findings: list[Finding] = []
        for tool in context.tools:
            properties = tool.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            for name in properties:
                if str(name).lower() not in URL_PARAMS:
                    continue
                text = response_text(call_tool(context, tool.name, {str(name): CANARY_URL}))
                if REFUSAL_SIGNALS.search(text):
                    continue
                if not ATTEMPT_SIGNALS.search(text):
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        severity=self.severity,
                        title=(
                            f"Tool {tool.name!r} parameter {name!r} did not refuse an "
                            f"arbitrary outbound destination (unconfirmed)"
                        ),
                        cwe=self.cwe,
                        taxonomy_refs=self.taxonomy_refs,
                        evidence=Evidence(
                            kind=EvidenceKind.TRANSCRIPT,
                            excerpt=(
                                f"tools/call {tool.name} {{{name!r}: {CANARY_URL!r}}}\n"
                                f"server response text matched a connection-attempt "
                                f"pattern rather than a policy refusal:\n{text[:200]}\n"
                                f"This does not confirm an outbound connection actually "
                                f"occurred: there is no out-of-band observation channel, "
                                f"only the target's own error text. info severity reflects "
                                f"that this is an unconfirmed signal, not a proven SSRF."
                            ),
                        ),
                        reproduction=context.reproduction(self.id),
                        claim=Claim(
                            value=f"{tool.name}.{name}",
                            method=Method.DETERMINISTIC,
                            derivation=Derivation.PROBE,
                            observed_at=datetime.now(UTC),
                            caveat=(
                                "No out-of-band channel confirms a connection attempt; "
                                "this is a text-pattern match on the server's own error, "
                                "not an independent observation."
                            ),
                        ),
                    )
                )
        return findings


CHECK = SsrfCheck()
