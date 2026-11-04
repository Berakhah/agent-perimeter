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
from agent_perimeter.instrument.canary import Canary

MAX_RESULT_CHARS = 2048
_UNDECODABLE = "[REDACTED:undecodable]"
_MAX_DECODE_ROUNDS = 32  # safety cap; decoding runs to a fixpoint, each round shortens

# The shared patterns anchor on \b for scanner precision (docs/methodology.md
# depends on that). Here a miss is a leak, so the anchors are dropped.
_UNANCHORED: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern.pattern.replace(r"\b", ""), pattern.flags))
    for name, pattern in SECRET_PATTERNS
)

# SECRET_KEY_NAME plus the header-style names it does not cover.
_AUTH_KEY_NAME = re.compile(r"(^|[_-])auth([_-]|$)|authori[sz]ation|cookie", re.IGNORECASE)


def _is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_NAME.search(key) or _AUTH_KEY_NAME.search(key))


def _replacer(name: str) -> Callable[[re.Match[str]], str]:
    def _sub(match: re.Match[str]) -> str:
        fingerprint = SecretFingerprint.of(match.group(0), location="transcript")
        return f"[REDACTED:{name}:{fingerprint.prefix}...{fingerprint.last4}]"

    return _sub


def _apply_patterns(text: str) -> str:
    for name, pattern in _UNANCHORED:
        text = pattern.sub(_replacer(name), text)
    return text


def _redact_patterns(text: str, canary: Canary | None) -> str:
    # This run's canary token is split out first so a boundary-free pattern
    # (e.g. "desk-AP-CANARY-..." reading as "sk-...") cannot swallow one. Only
    # the exact token is preserved, never a lookalike.
    if canary is None or canary.token not in text:
        return _apply_patterns(text)
    split = canary.token.join(_apply_patterns(piece) for piece in text.split(canary.token))
    # A secret with the token spliced inside leaves both halves below pattern
    # length. If removing the token reveals more secrets than the split found,
    # drop the token and keep only the redacted stripped form.
    stripped = _apply_patterns(text.replace(canary.token, ""))
    if stripped.count("[REDACTED:") > split.count("[REDACTED:"):
        return stripped
    return split


def redact(text: str, canary: Canary | None = None) -> str:
    """Replace every recognised credential in `text`, including percent-encoded ones.

    Only `canary`'s exact token is preserved; None preserves nothing.
    """
    plain = _redact_patterns(text, canary)
    decoded = text
    for _ in range(_MAX_DECODE_ROUNDS):
        if "%" not in decoded:
            break
        step = unquote(decoded)
        if step == decoded:
            break
        decoded = step
    if "%" in decoded and unquote(decoded) != decoded:
        # Still decoding after the cap: a deeper encoding than any real client
        # sends. Fail closed rather than persist a body that may hold a secret.
        # The token is kept only if it appeared verbatim; a deep-encoded token
        # is lost, which is the safe direction.
        if canary is not None and canary.token in text:
            return f"{_UNDECODABLE} {canary.token}"
        return _UNDECODABLE
    # Decode fully before judging, so a secret one level deeper than another is
    # not left encoded. If decoding revealed anything, keep only the redacted
    # decoded form, so the raw secret survives in neither encoding.
    cleaned = _redact_patterns(decoded, canary)
    return cleaned if cleaned != decoded and decoded != text else plain


def _secret_value(value: object, canary: Canary) -> str:
    """The stand-in for a value under a secret-named key; only this run's token is kept."""
    if canary.token in str(value):
        return f"[REDACTED:secret-key] {canary.token}"
    return "[REDACTED:secret-key]"


def _clean_key(key: object, canary: Canary) -> object:
    return redact(key, canary) if isinstance(key, str) else key


def _clean_entry(key: object, item: object, canary: Canary) -> object:
    if isinstance(key, str) and _is_secret_key(key):
        return _secret_value(item, canary)
    return _clean(item, canary)


def _clean(value: object, canary: Canary) -> object:
    if isinstance(value, str):
        return redact(value, canary)
    if isinstance(value, dict):
        return {
            _clean_key(key, canary): _clean_entry(key, item, canary) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_clean(item, canary) for item in value]
    return value


@dataclass
class Recorder:
    canary: Canary
    _calls: list[dict[str, object]] = field(default_factory=list)
    _sinks: list[str] = field(default_factory=list)
    _weak_sinks: list[str] = field(default_factory=list)

    def record_call(
        self, name: str, arguments: object, result_text: str, *, injected: bool
    ) -> None:
        entry: dict[str, object] = {
            "name": redact(name, self.canary),
            "arguments": _clean(arguments, self.canary),
            "result": redact(result_text, self.canary)[:MAX_RESULT_CHARS],
        }
        if injected:
            entry["injected"] = True
        self._calls.append(entry)

    def set_sinks(self, sinks: frozenset[str], weak: frozenset[str] = frozenset()) -> None:
        """Record the proxy's sinks (latest wins).

        `sinks` have a schema-, name- or probe-derived edge; `weak` are inferred
        from description prose only.
        """
        self._sinks = sorted(redact(name, self.canary) for name in sinks)
        self._weak_sinks = sorted(redact(name, self.canary) for name in weak)

    def to_transcript(self) -> dict[str, object]:
        return {
            "tool_calls": list(self._calls),
            "canary": {
                "nonce": self.canary.nonce,
                "sinks": list(self._sinks),
                "weak_sinks": list(self._weak_sinks),
            },
        }
