# agent_perimeter/checks/secrets/history_scan.py
"""Credentials still reachable in git history after removal from HEAD.

Deleting a secret from the working tree does not unpublish it. The commit that
introduced it remains fetchable by anyone who can clone the repository, which
is why GitGuardian's count includes values their owners believe are gone.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from agent_perimeter._contracts import SecretFingerprint, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets.config_scan import build_finding
from agent_perimeter.checks.secrets.patterns import (
    ENTROPY_FLOOR,
    MIN_LENGTH,
    SECRET_KEY_NAME,
    is_placeholder,
    matches_known_pattern,
)
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding

ASSIGNMENT = re.compile(r'["\']?([A-Za-z0-9_.-]+)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']')
COMMIT_LINE = re.compile(r"^commit ([0-9a-f]{40})$")

HISTORY_SCAN_TIMEOUT = 120.0
"""Wall-clock budget for the whole `git log` walk, not per-line."""


def iter_history_blobs(repo_path: Path) -> Iterator[tuple[str, str]]:
    """Yield (location, added_line) for every addition in history.

    Streams `git log` output line by line instead of buffering it: a large
    repository's full `-p --all` history can be gigabytes, and the scanner
    only ever needs one line in memory at a time.
    """
    try:
        proc = subprocess.Popen(
            ["git", "log", "-p", "--no-color", "--unified=0", "--all"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return

    # A per-line deadline check can't fire on a process that never writes a
    # line: the blocking read just sits there. Killing the process from a
    # separate thread closes its stdout, which unblocks the read with EOF
    # regardless of whether output ever arrived.
    timer = threading.Timer(HISTORY_SCAN_TIMEOUT, proc.kill)
    timer.start()
    commit = "unknown"
    stdout = proc.stdout
    try:
        if stdout is not None:
            for line in stdout:
                line = line.rstrip("\n")
                match = COMMIT_LINE.match(line)
                if match:
                    commit = match.group(1)[:12]
                    continue
                if line.startswith("+") and not line.startswith("+++"):
                    yield f"git:{commit}", line[1:]
    finally:
        timer.cancel()
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)


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
                # Same precedence as patterns.scan_mapping, which config_scan
                # and env_scan get for free: a published credential prefix
                # fires regardless of borderline entropy, but never skips the
                # placeholder check — GitHub/OpenAI/GitLab's own documented
                # placeholder conventions use a real prefix shape. A commit
                # diff is full of URLs, paths and UUIDs under `*_key`/
                # `*_token` names — without the placeholder gate they all
                # fired at CRITICAL here while the identical value was
                # correctly ignored by config_scan.
                if is_placeholder(value):
                    continue
                known = matches_known_pattern(value)
                fingerprint = SecretFingerprint.of(value, location=f"{location}:{key}")
                if known is None and fingerprint.entropy < ENTROPY_FLOOR:
                    continue
                if fingerprint.sha256 in seen:
                    continue
                seen.add(fingerprint.sha256)
                findings.append(
                    build_finding(self.id, context, fingerprint, hmac_key=self.hmac_key)
                )
        return findings


CHECK = HistoryScanCheck()
