"""Wire-level transcript, with secrets redacted before anything is stored.

Hard constraint 3: a raw secret never reaches the transcript file. Redaction
runs before truncation so a secret straddling the cut is replaced whole, not
half-leaked. Arguments are redacted but not truncated, so the canary token
survives however long the surrounding string is.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_perimeter._contracts import SecretFingerprint
from agent_perimeter.checks.secrets.patterns import SECRET_PATTERNS
from agent_perimeter.instrument.canary import Canary

MAX_RESULT_CHARS = 2048


def _replacer(name: str) -> Callable[[re.Match[str]], str]:
    def _sub(match: re.Match[str]) -> str:
        fingerprint = SecretFingerprint.of(match.group(0), location="transcript")
        return f"[REDACTED:{name}:{fingerprint.prefix}...{fingerprint.last4}]"

    return _sub


def redact(text: str) -> str:
    for name, pattern in SECRET_PATTERNS:
        text = pattern.sub(_replacer(name), text)
    return text


def _clean(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            (redact(key) if isinstance(key, str) else key): _clean(item)
            for key, item in value.items()
        }
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
            "name": name,
            "arguments": _clean(arguments),
            "result": redact(result_text)[:MAX_RESULT_CHARS],
        }
        if injected:
            entry["injected"] = True
        self._calls.append(entry)

    def to_transcript(self) -> dict[str, object]:
        return {"tool_calls": list(self._calls), "canary": {"nonce": self.canary.nonce}}
