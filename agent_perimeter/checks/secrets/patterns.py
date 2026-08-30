# agent_perimeter/checks/secrets/patterns.py
"""Credential-shaped keys, real prefix patterns, placeholder rejection, and
the export transform that keeps a raw hash out of every exported artifact.

Revision 2026-08-29 section 5.5: entropy + length alone is a heavy false-
positive source (file paths, URLs, UUIDs, "your-api-key-here-replace-me" —
the dominant content of public .mcp.json files). SECRET_PATTERNS was declared
in this module's interface from the start and never implemented; it is now.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from pathlib import Path

from agent_perimeter._contracts import SecretFingerprint

SECRET_KEY_NAME = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|credential|bearer|"
    r"access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)

# Below this, a value is a placeholder like "changeme" rather than a credential.
ENTROPY_FLOOR = 3.0
MIN_LENGTH = 16

# Real, published credential prefix shapes. A prefix match raises precision
# far more than entropy alone — it fires regardless of borderline entropy,
# and skips the placeholder check, since a real key with this shape is
# vanishingly unlikely to also be a placeholder string.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_bot_token", re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,}\b")),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
)

# Values that look credential-shaped by entropy/length but are the dominant
# false-positive content of real .mcp.json files.
_PLACEHOLDER_WORDS = re.compile(
    r"(changeme|your[_-]?.*[_-]?(key|token|secret)|replace[_-]?me|example|"
    r"placeholder|xxxx|dummy|todo|fixme)",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    if _PLACEHOLDER_WORDS.search(value):
        return True
    try:
        uuid.UUID(value)
        return True  # a bare UUID is not a credential
    except ValueError:
        pass
    # URL or file path
    return value.startswith(("http://", "https://", "/", "./", "../")) or "\\" in value


def matches_known_pattern(value: str) -> str | None:
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return name
    return None


def scan_mapping(data: object, source: str, prefix: str = "") -> list[SecretFingerprint]:
    """Walk a nested mapping, fingerprinting credential-shaped values."""
    found: list[SecretFingerprint] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict | list):
                found.extend(scan_mapping(value, source, path))
                continue
            if not isinstance(value, str):
                continue
            if not SECRET_KEY_NAME.search(str(key)):
                continue
            if len(value) < MIN_LENGTH:
                continue
            known = matches_known_pattern(value)
            if known is None:
                if is_placeholder(value):
                    continue
                candidate = SecretFingerprint.of(value, location=f"{source}:{path}")
                if candidate.entropy < ENTROPY_FLOOR:
                    continue
                found.append(candidate)
            else:
                found.append(SecretFingerprint.of(value, location=f"{source}:{path}"))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            if isinstance(item, dict | list):
                found.extend(scan_mapping(item, source, f"{prefix}[{index}]"))
            elif isinstance(item, str) and matches_known_pattern(item) is not None:
                # A list item has no key name to gate on, so only a known
                # prefix match qualifies it — the entropy-only fallback stays
                # dict-only, or ordinary list content (URLs, paths in argv
                # arrays) would flood this with false positives.
                found.append(SecretFingerprint.of(item, location=f"{source}:{prefix}[{index}]"))
    return found


# --- Export transform (revision 5.5) -----------------------------------------

_KEY_PATH = Path.home() / ".agent-perimeter" / "hmac.key"


def _installation_key() -> bytes:
    """A per-installation HMAC key, generated once and persisted locally.

    Never the raw digest's salt for anything that stays in the database —
    only for values that leave the process (SARIF, HTML). Losing this file
    just means exported fingerprints stop correlating across scans; it is
    not itself sensitive material.
    """
    if _KEY_PATH.exists():
        return bytes.fromhex(_KEY_PATH.read_text().strip())
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = uuid.uuid4().bytes + uuid.uuid4().bytes
    _KEY_PATH.write_text(key.hex())
    return key


def export_fingerprint(fingerprint: SecretFingerprint, *, hmac_key: bytes | None = None) -> str:
    """The only form of a fingerprint allowed into SARIF, HTML, or a screenshot.

    HMAC-SHA256 of the raw digest with a per-installation key, truncated to
    16 hex characters. An unsalted hash confirms a guessed or previously
    leaked credential instantly; this does not.
    """
    key = hmac_key if hmac_key is not None else _installation_key()
    return hmac.new(key, fingerprint.sha256.encode(), hashlib.sha256).hexdigest()[:16]
