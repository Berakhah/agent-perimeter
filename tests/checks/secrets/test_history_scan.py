import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.secrets.history_scan import HistoryScanCheck
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint

# Synthetic, structurally valid, never issued. gitleaks-safe: not a real prefix.
FAKE_KEY = "sk-test-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"

# Fixed test key so these tests never touch the real ~/.agent-perimeter/hmac.key
# (export_fingerprint's default path). A check instance built with it, never
# the CHECK singleton, which is reserved for production's real installation
# key. Same convention as tests/checks/secrets/test_fingerprint_and_scans.py.
_TEST_HMAC_KEY = b"test-key-0123456789abcdef01234567"
_CHECK = HistoryScanCheck(hmac_key=_TEST_HMAC_KEY)


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(repo: Path | None) -> ScanContext:
    raw: dict[str, dict[str, object]] = {}
    if repo is not None:
        raw["_repo_path"] = {"path": str(repo)}
    return ScanContext(
        target="local",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-22 brief, same as task-21): Feature.STATELESS_META
            # does not exist — no feature is needed for these tests.
            features=frozenset(),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw=raw,
    )


@pytest.fixture
def repo_with_removed_secret(tmp_path: Path) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "Test")
    config = tmp_path / ".mcp.json"
    config.write_text(f'{{"env": {{"API_KEY": "{FAKE_KEY}"}}}}')
    git("add", ".mcp.json")
    git("commit", "-qm", "add config")
    config.write_text('{"env": {"API_KEY": "${API_KEY}"}}')
    git("add", ".mcp.json")
    git("commit", "-qm", "remove secret")
    return tmp_path


def test_secret_removed_from_head_is_still_found_in_history(
    repo_with_removed_secret: Path,
) -> None:
    findings = _CHECK.run(_context(repo_with_removed_secret))
    assert len(findings) >= 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cwe == "CWE-798"


def test_no_raw_secret_appears_in_the_finding(repo_with_removed_secret: Path) -> None:
    for finding in _CHECK.run(_context(repo_with_removed_secret)):
        assert FAKE_KEY not in finding.evidence.excerpt
        assert FAKE_KEY not in finding.title
        assert FAKE_KEY not in str(finding.claim.value)


def test_repo_without_secrets_is_clean(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    assert _CHECK.run(_context(tmp_path)) == []


def test_no_repo_path_means_nothing_to_scan() -> None:
    assert _CHECK.run(_context(None)) == []


# A .mcp.json diff is full of URLs, file paths and UUIDs sitting under keys
# named `*_token` / `*_key`. config_scan and env_scan filter those through
# `scan_mapping`'s placeholder gate; history_scan reimplemented the entropy
# and key-name checks but not that one, so the identical value fired a
# CRITICAL finding here and nothing there. Mirrors
# test_fingerprint_and_scans.py::test_placeholder_shaped_values_are_not_reported.
PLACEHOLDER_SHAPED = (
    "https://cdn.example.test/v1/aZ9kQm2Xp7Lw",
    "https://example.test/callback",
    "/home/user/.config/mcp/aZ9kQm2Xp7Lw",
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "your-api-key-here-replace-me",
)


@pytest.fixture
def repo_with_placeholders(tmp_path: Path) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "Test")
    entries = ",\n    ".join(
        f'"API_KEY_{index}": "{value}"' for index, value in enumerate(PLACEHOLDER_SHAPED)
    )
    (tmp_path / ".mcp.json").write_text('{\n  "env": {\n    ' + entries + "\n  }\n}\n")
    git("add", ".mcp.json")
    git("commit", "-qm", "add config")
    return tmp_path


def test_placeholder_shaped_values_in_history_are_not_reported(
    repo_with_placeholders: Path,
) -> None:
    findings = _CHECK.run(_context(repo_with_placeholders))
    assert findings == [], [f.title for f in findings]


def test_a_known_prefix_still_fires_even_where_a_placeholder_would_not(tmp_path: Path) -> None:
    """Mirrors scan_mapping's precedence: a real credential prefix beats the
    placeholder heuristic, it does not get filtered by it."""

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "Test")
    # Deliberately also placeholder-shaped (contains "example") — the known
    # prefix has to win.
    (tmp_path / ".mcp.json").write_text(
        '{"env": {"API_KEY": "ghp_exampleaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
    )
    git("add", ".mcp.json")
    git("commit", "-qm", "add config")
    assert len(_CHECK.run(_context(tmp_path))) == 1
