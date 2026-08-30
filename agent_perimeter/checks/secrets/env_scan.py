# agent_perimeter/checks/secrets/env_scan.py
"""Credentials in the environment handed to a stdio server."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets.config_scan import build_finding
from agent_perimeter.checks.secrets.patterns import scan_mapping
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding


@dataclass(frozen=True)
class EnvScanCheck:
    id: str = "secrets.env_scan"
    cwe: str = "CWE-798"
    taxonomy_refs: tuple[str, ...] = ("owasp-llm:LLM02",)
    severity: Severity = Severity.CRITICAL
    requires_auth: bool = False
    requires_model: bool = False
    requires_features: frozenset[Feature] = field(default_factory=frozenset)
    hmac_key: bytes | None = None
    """Injectable for test hermeticity; None (the `CHECK` singleton's default)
    falls through to the real per-installation key. See `build_finding`."""

    def run(self, context: ScanContext) -> list[Finding]:
        env = context.raw.get("_env")
        if not env:
            return []
        return [
            build_finding(self.id, context, fp, hmac_key=self.hmac_key)
            for fp in scan_mapping(env, "env")
        ]


CHECK = EnvScanCheck()
