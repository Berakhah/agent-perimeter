"""Turn drift events into text a human can read safely (spec §5.2).

Everything here treats the description as data. `for_terminal` exists
because a tool description is attacker-authored and the `drift` command
prints it: an embedded `ESC[2J` must not repaint the operator's terminal.
"""

from __future__ import annotations

from collections.abc import Sequence
from difflib import SequenceMatcher
from itertools import groupby
from typing import Literal

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.descriptions.unicode_anomaly import (
    BIDI_OVERRIDES,
    TAG_CHARACTERS,
    ZERO_WIDTH,
)
from agent_perimeter.model.drift import DriftEvent, DriftField

# The plain Severity StrEnum sorts alphabetically; this is the real ranking.
# Same table as cli.SEVERITY_RANK, kept here so checks never import cli.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# SequenceMatcher is quadratic in the worst case; above this the excerpt
# falls back to the hash summary and says so.
MAX_DIFF_TOKENS = 4000

DiffRun = tuple[Literal["equal", "insert", "delete", "replace-summary"], str]

_KEEP = {"\n", "\t"}
_INVISIBLE = BIDI_OVERRIDES | ZERO_WIDTH | TAG_CHARACTERS


def word_diff(old: str, new: str) -> list[DiffRun]:
    """Generate a list of word-level diff runs between two strings."""
    a = old.split()
    b = new.split()
    if len(a) > MAX_DIFF_TOKENS or len(b) > MAX_DIFF_TOKENS:
        return [
            (
                "replace-summary",
                f"{len(a)} tokens → {len(b)} tokens; diff too large to render, hashes differ",
            )
        ]
    runs: list[DiffRun] = []
    for op, i1, i2, j1, j2 in SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if op == "equal":
            runs.append(("equal", " ".join(a[i1:i2])))
        elif op == "delete":
            runs.append(("delete", " ".join(a[i1:i2])))
        elif op == "insert":
            runs.append(("insert", " ".join(b[j1:j2])))
        else:  # replace
            runs.append(("delete", " ".join(a[i1:i2])))
            runs.append(("insert", " ".join(b[j1:j2])))
    return runs


def for_terminal(text: str) -> str:
    """Escape anything that could steer a terminal or hide from a reader."""
    out: list[str] = []
    for ch in text:
        point = ord(ch)
        if ch in _KEEP:
            out.append(ch)
        elif point < 0x20 or 0x7F <= point < 0xA0 or point in _INVISIBLE:
            out.append(f"\\u{{{point:X}}}")
        else:
            out.append(ch)
    return "".join(out)


def _short(hash_value: str | None) -> str:
    """Return the first 12 chars of a hash or '(absent)'."""
    return "(absent)" if hash_value is None else hash_value[:12]


def render_excerpt(event: DriftEvent) -> str:
    """The `Evidence.excerpt` for one event.

    Old and new text appear only here, as data, marked `-`/`+` per run.
    """
    if (
        event.field is DriftField.DESCRIPTION
        and event.old_value is not None
        and event.new_value is not None
    ):
        parts: list[str] = []
        for kind, text in word_diff(event.old_value, event.new_value):
            if kind == "equal":
                parts.append(text)
            elif kind == "delete":
                parts.append(f"-{text}")
            elif kind == "insert":
                parts.append(f"+{text}")
            else:
                parts.append(f"[{text}]")
        return " ".join(parts)
    return f"{event.field.value}: {_short(event.old_hash)} → {_short(event.new_hash)}"


def render_events(events: Sequence[DriftEvent]) -> list[str]:
    """Terminal blocks, one per tool, every line sanitised."""
    lines: list[str] = []
    for key, group in groupby(events, key=lambda e: e.tool_name):
        tool_events = list(group)
        fields = ", ".join(e.field.value for e in tool_events)
        worst = min(tool_events, key=lambda e: SEVERITY_RANK[e.severity]).severity.value
        lines.append(for_terminal(f"== {key} — {fields} — {worst}"))
        for event in tool_events:
            if (
                event.field is DriftField.DESCRIPTION
                and event.old_value is not None
                and event.new_value is not None
            ):
                for kind, text in word_diff(event.old_value, event.new_value):
                    prefix = {"equal": " ", "delete": "-", "insert": "+"}.get(kind, "?")
                    lines.append(for_terminal(f"{prefix}{text}"))
            else:
                lines.append(for_terminal(render_excerpt(event)))
    return lines
