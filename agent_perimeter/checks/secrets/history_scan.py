# agent_perimeter/checks/secrets/history_scan.py
"""Credentials still reachable in git history after removal from HEAD.

Deleting a secret from the working tree does not unpublish it. The commit that
introduced it remains fetchable by anyone who can clone the repository, which
is why GitGuardian's count includes values their owners believe are gone.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from agent_perimeter._contracts import SecretFingerprint, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets.config_scan import build_finding
from agent_perimeter.checks.secrets.patterns import ENTROPY_FLOOR, MIN_LENGTH, SECRET_KEY_NAME
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding

ASSIGNMENT = re.compile(r'["\']?([A-Za-z0-9_.-]+)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']')
COMMIT_LINE = re.compile(r"^commit ([0-9a-f]{40})$")


def iter_history_blobs(repo_path: Path) -> Iterator[tuple[str, str]]:
    """Yield (location, added_line) for every addition in history."""
    try:
        completed = subprocess.run(
            ["git", "log", "-p", "--no-color", "--unified=0", "--all"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return

    commit = "unknown"
    for line in completed.stdout.splitlines():
        match = COMMIT_LINE.match(line)
        if match:
            commit = match.group(1)[:12]
            continue
        if line.startswith("+") and not line.startswith("+++"):
            yield f"git:{commit}", line[1:]


@dataclass(frozen=True)
class HistoryScanCheck:
    id: str = "secrets.history_scan"
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
        marker = context.raw.get("_repo_path")
        if not marker or "path" not in marker:
            return []
        repo_path = Path(str(marker["path"]))

        seen: set[str] = set()
        findings: list[Finding] = []
        for location, line in iter_history_blobs(repo_path):
            for key, value in ASSIGNMENT.findall(line):
                if not SECRET_KEY_NAME.search(key) or len(value) < MIN_LENGTH:
                    continue
                fingerprint = SecretFingerprint.of(value, location=f"{location}:{key}")
                if fingerprint.entropy < ENTROPY_FLOOR or fingerprint.sha256 in seen:
                    continue
                seen.add(fingerprint.sha256)
                findings.append(
                    build_finding(self.id, context, fingerprint, hmac_key=self.hmac_key)
                )
        return findings


CHECK = HistoryScanCheck()
