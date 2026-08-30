# agent_perimeter/checks/secrets/config_scan.py
"""Credentials in MCP client configuration.

GitGuardian counted 24,008 unique secrets in MCP-related configuration files
across public GitHub in March 2026, 2,117 of them still valid. This is the one
finding class with a hard published prevalence behind it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from agent_perimeter._contracts import Claim, Derivation, Method, SecretFingerprint, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets.patterns import export_fingerprint, scan_mapping
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding, FindingLocation


def build_finding(
    check_id: str,
    context: ScanContext,
    fingerprint: SecretFingerprint,
    *,
    location: FindingLocation | None = None,
    hmac_key: bytes | None = None,
) -> Finding:
    """Evidence quotes the fingerprint. The value is never rendered anywhere.

    Revision 5.5: the excerpt carries `export_fingerprint`'s HMAC'd, truncated
    form, never `fingerprint.sha256` directly — the raw digest is an unsalted
    oracle the moment it leaves the process (this excerpt lands in SARIF,
    which lands in CI logs and GitHub). The raw sha256 stays in `claim.value`
    only if a caller needs local, in-database correlation; it is Finding's
    responsibility, not this function's, to keep that value out of any
    exported artifact — Task 24's SARIF emitter reads only the excerpt.

    `hmac_key` defaults to None, which falls through to `export_fingerprint`'s
    own per-installation key at `~/.agent-perimeter/hmac.key`. Callers that
    need a fixed key (tests, hermetic CI) pass one explicitly instead of
    touching the real filesystem.
    """
    exported = export_fingerprint(fingerprint, hmac_key=hmac_key)
    return Finding(
        check_id=check_id,
        severity=Severity.CRITICAL,
        title=f"Credential-shaped value at {fingerprint.location}",
        cwe="CWE-798",
        taxonomy_refs=("owasp-mcp:MCP01", "owasp-llm:LLM02"),
        evidence=Evidence(
            kind=EvidenceKind.EXCERPT,
            excerpt=(
                f"location: {fingerprint.location}\n"
                f"fingerprint: {exported} (HMAC-SHA256, truncated, per-installation key)\n"
                f"entropy: {fingerprint.entropy:.2f}\n"
                f"prefix: {fingerprint.prefix}…{fingerprint.last4}\n"
                f"value: NOT RECORDED (hard constraint 3)"
            ),
            redacted=True,
        ),
        reproduction=context.reproduction(check_id),
        claim=Claim(
            value=exported,
            method=Method.DETERMINISTIC,
            derivation=Derivation.ARTIFACT,
            observed_at=datetime.now(UTC),
            caveat="Fingerprint only; never validated against a live service",
        ),
        location=location,
    )


@dataclass(frozen=True)
class ConfigScanCheck:
    id: str = "secrets.config_scan"
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
        config = context.raw.get("_config")
        if not config:
            return []
        source_path = context.raw.get("_config_path", {}).get("path")
        return [
            build_finding(
                self.id, context, fp, location=_locate(source_path, fp), hmac_key=self.hmac_key
            )
            for fp in scan_mapping(config, ".mcp.json")
        ]


def _locate(source_path: object, fingerprint: SecretFingerprint) -> FindingLocation | None:
    """A real (uri, line) anchor for Task 24's SARIF physicalLocation.

    Genuine, not invented: greps the real config file for the credential's
    own key name and reports the first matching line. Falls back to None
    (Task 24 anchors to the scan-profile artifact instead) when there is no
    file to point at, or the key does not appear on its own line — e.g. a
    minified single-line JSON file, where "a line number" is not meaningful.
    """
    if not source_path:
        return None
    key = fingerprint.location.rsplit(".", 1)[-1]
    try:
        lines = Path(str(source_path)).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for lineno, text in enumerate(lines, start=1):
        if key in text:
            return FindingLocation(uri=str(source_path), line=lineno)
    return None


CHECK = ConfigScanCheck()
