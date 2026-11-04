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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import unquote

from agent_perimeter._contracts import SecretFingerprint
from agent_perimeter.checks.injection.path_proof import SinkClass
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


# Why the proxy's tool listing stopped early. A fixed vocabulary, never
# server-supplied text (a cursor may embed a credential), so the adapter can
# quote a recognised reason verbatim and refuse anything else.
LISTING_PAGE_FAILED = (
    "a tools/list page after the first failed; sources and sinks were computed from "
    "the pages received before it"
)
# Sticky, and true whether or not a later listing recovered: calls before the
# recovery (all of them, if it never came) were made with no tools known.
LISTING_FIRST_PAGE_FAILED = (
    "the first tools/list page failed; until a later listing succeeded no tools were "
    "known, so calls made before then got no canary"
)
LISTING_REPEAT_CURSOR = (
    "the server repeated a tools/list cursor; sources and sinks were computed from the "
    "pages received before it"
)
LISTING_PAGE_CAP = (
    "the server still offered a next tools/list page at the page cap; sources and sinks "
    "were computed from the pages received"
)
LISTING_REASONS = frozenset(
    {LISTING_PAGE_FAILED, LISTING_FIRST_PAGE_FAILED, LISTING_REPEAT_CURSOR, LISTING_PAGE_CAP}
)


@dataclass
class Recorder:
    """The transcript. Sinks are a session-wide union that never shrinks, and
    each call also carries the receiving tool's classification at call time,
    so a later, smaller re-list cannot downgrade an earlier bait call."""

    canary: Canary
    _calls: list[dict[str, object]] = field(default_factory=list)
    _sinks: dict[str, SinkClass] = field(default_factory=dict)
    _listing_incomplete: str | None = None

    def record_call(
        self,
        name: str,
        arguments: object,
        result_text: str,
        *,
        injected: bool,
        sink: SinkClass | None = None,
    ) -> None:
        entry: dict[str, object] = {
            "name": redact(name, self.canary),
            "arguments": _clean(arguments, self.canary),
            "result": redact(result_text, self.canary)[:MAX_RESULT_CHARS],
        }
        if injected:
            entry["injected"] = True
        if sink is not None:
            entry["sink"] = sink.to_json()
        self._calls.append(entry)

    def add_sinks(self, classes: Mapping[str, SinkClass]) -> None:
        """Fold the proxy's current sinks into the session union.

        A name once seen as a sink stays one; backed beats weak, and a backed
        sink keeps its strongest derivation.
        """
        for name, found in classes.items():
            key = redact(name, self.canary)
            self._sinks[key] = found.stronger(self._sinks.get(key))

    def mark_listing_incomplete(self, reason: str) -> None:
        """Record that the proxy's listing stopped early. Sticky: the first reason is kept."""
        if self._listing_incomplete is None:
            self._listing_incomplete = reason

    def to_transcript(self) -> dict[str, object]:
        backed = {name: c for name, c in self._sinks.items() if c.backed}
        canary: dict[str, object] = {
            "nonce": self.canary.nonce,
            "sinks": sorted(backed),
            "weak_sinks": sorted(name for name, c in self._sinks.items() if not c.backed),
            "sink_derivations": {name: backed[name].derivation.value for name in sorted(backed)},
        }
        if self._listing_incomplete is not None:
            canary["listing_incomplete"] = self._listing_incomplete
        return {"tool_calls": list(self._calls), "canary": canary}
