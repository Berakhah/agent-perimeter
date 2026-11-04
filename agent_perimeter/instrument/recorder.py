"""Wire-level transcript, with recognised secrets redacted before anything is stored.

Hard constraint 3. What is redacted: any substring in a recognised credential
format (SECRET_PATTERNS, matched without word boundaries so a secret glued to
`key_` or `x` is still caught, and after percent-decoding so a URL-encoded one
is too), and the whole value of any entry whose key looks secret-named. What is
not: a credential in a format we do not recognise, under an innocuous key, may
be recorded verbatim. Over-redaction is accepted; the canary token is the one
thing always kept, so the adapter can still see an obedient call.

Redaction runs before truncation so a secret straddling the cut is replaced
whole, not half-leaked. Arguments are redacted but not truncated, so the canary
token survives however long the surrounding string is.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import unquote

from agent_perimeter._contracts import SecretFingerprint
from agent_perimeter.checks.secrets.patterns import SECRET_KEY_NAME, SECRET_PATTERNS
from agent_perimeter.instrument.canary import PREFIX, Canary

MAX_RESULT_CHARS = 2048
_MAX_DECODE_ROUNDS = 3  # %253D -> %3D -> =

# The shared patterns anchor on \b for scanner precision (docs/methodology.md
# depends on that). Here a miss is a leak, so the anchors are dropped.
_UNANCHORED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern.pattern.replace(r"\b", ""), pattern.flags))
    for name, pattern in SECRET_PATTERNS
)

# SECRET_KEY_NAME plus the header-style names it does not cover.
_AUTH_KEY_NAME = re.compile(r"(^|[_-])auth([_-]|$)|authori[sz]ation|cookie", re.IGNORECASE)

_CANARY_TOKEN = re.compile(re.escape(PREFIX) + r"[0-9a-f]{16}")


def _is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_NAME.search(key) or _AUTH_KEY_NAME.search(key))


def _replacer(name: str) -> Callable[[re.Match[str]], str]:
    def _sub(match: re.Match[str]) -> str:
        fingerprint = SecretFingerprint.of(match.group(0), location="transcript")
        return f"[REDACTED:{name}:{fingerprint.prefix}...{fingerprint.last4}]"

    return _sub


def _redact_patterns(text: str) -> str:
    # Canary tokens are split out first so a boundary-free pattern
    # (e.g. "desk-AP-CANARY-..." reading as "sk-...") cannot swallow one.
    pieces = _CANARY_TOKEN.split(text)
    tokens = _CANARY_TOKEN.findall(text)
    redacted: list[str] = []
    for index, piece in enumerate(pieces):
        for name, pattern in _UNANCHORED:
            piece = pattern.sub(_replacer(name), piece)
        redacted.append(piece)
        if index < len(tokens):
            redacted.append(tokens[index])
    return "".join(redacted)


def redact(text: str) -> str:
    """Replace every recognised credential in `text`, including percent-encoded ones."""
    plain = _redact_patterns(text)
    decoded = text
    for _ in range(_MAX_DECODE_ROUNDS):
        if "%" not in decoded:
            break
        step = unquote(decoded)
        if step == decoded:
            break
        decoded = step
        cleaned = _redact_patterns(decoded)
        if cleaned != decoded:
            # Decoding revealed a secret: keep only the redacted decoded form,
            # so the raw secret survives in neither encoding.
            return cleaned
    return plain


def _secret_value(value: object) -> str:
    """The stand-in for a value under a secret-named key; only canary tokens are kept."""
    tokens = _CANARY_TOKEN.findall(str(value))
    return " ".join(["[REDACTED:secret-key]", *tokens])


def _clean_key(key: object) -> object:
    return redact(key) if isinstance(key, str) else key


def _clean_entry(key: object, item: object) -> object:
    if isinstance(key, str) and _is_secret_key(key):
        return _secret_value(item)
    return _clean(item)


def _clean(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {_clean_key(key): _clean_entry(key, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


@dataclass
class Recorder:
    canary: Canary
    _calls: list[dict[str, object]] = field(default_factory=list)

    def record_call(
        self, name: str, arguments: object, result_text: str, *, injected: bool
    ) -> None:
        entry: dict[str, object] = {
            "name": redact(name),
            "arguments": _clean(arguments),
            "result": redact(result_text)[:MAX_RESULT_CHARS],
        }
        if injected:
            entry["injected"] = True
        self._calls.append(entry)

    def to_transcript(self) -> dict[str, object]:
        return {"tool_calls": list(self._calls), "canary": {"nonce": self.canary.nonce}}
