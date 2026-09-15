"""Two snapshots in, an ordered list of changes out (spec §5.1).

Pure: no I/O, no clock. The runner, the CLI `drift` command and the eval
harness all call this one function, so there is exactly one definition of
"changed".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.drift import DRIFT_SEVERITY, DriftEvent, DriftField
from agent_perimeter.model.snapshot import SnapshotTool, ToolSnapshot, canonical_json


def positional_keys(names: Iterable[str]) -> list[str]:
    """`["x", "x", "y"]` -> `["x", "x#2", "y"]`: one key per position, in
    listing order. A repeated name (attacker-authored listings may repeat)
    gets `name#2`, `name#3` … so every copy is still addressable and the
    output stays deterministic. This is the one definition of "the key for
    a tool at this position" — every caller that needs to line up two
    listings of the same target by position (drift comparison, and the API's
    persistence/read paths) uses this function rather than its own."""
    keys: list[str] = []
    seen: dict[str, int] = {}
    for name in names:
        count = seen.get(name, 0) + 1
        seen[name] = count
        keys.append(name if count == 1 else f"{name}#{count}")
    return keys


def keyed_tools(snapshot: ToolSnapshot) -> dict[str, SnapshotTool]:
    """Index tools by their positional key; see `positional_keys`."""
    keys = positional_keys(tool.name for tool in snapshot.tools)
    return dict(zip(keys, snapshot.tools, strict=True))


def plain_name(key: str) -> str:
    """`x#2` -> `x`; a name that merely contains `#` is left alone."""
    name, sep, index = key.rpartition("#")
    return name if sep and index.isdigit() else key


def _side(field: DriftField, tool: SnapshotTool | None) -> tuple[str | None, str | None]:
    """(hash, value) for one side of an event; (None, None) when the tool is
    absent on that side. Added/removed events carry the description."""
    if tool is None:
        return None, None
    if field is DriftField.INPUT_SCHEMA:
        return tool.schema_hash, canonical_json(tool.input_schema)
    if field is DriftField.ANNOTATIONS:
        return tool.annotations_hash, canonical_json(tool.annotations)
    return tool.description_hash, tool.description


def _event(
    key: str,
    field: DriftField,
    old: SnapshotTool | None,
    new: SnapshotTool | None,
    now: datetime,
) -> DriftEvent:
    old_hash, old_value = _side(field, old)
    new_hash, new_value = _side(field, new)
    return DriftEvent(
        tool_name=key,
        field=field,
        old_hash=old_hash,
        new_hash=new_hash,
        old_value=old_value,
        new_value=new_value,
        severity=DRIFT_SEVERITY[field],
        detected_at=now,
    )


_PER_TOOL_FIELDS: tuple[tuple[DriftField, str], ...] = (
    (DriftField.DESCRIPTION, "description_hash"),
    (DriftField.INPUT_SCHEMA, "schema_hash"),
    (DriftField.ANNOTATIONS, "annotations_hash"),
)


def compare(baseline: ToolSnapshot, current: ToolSnapshot, *, now: datetime) -> list[DriftEvent]:
    if baseline.target != current.target:
        raise ValueError(
            f"baseline is for {baseline.target!r} but the current snapshot is for "
            f"{current.target!r}; drift is only meaningful for one target"
        )
    before = keyed_tools(baseline)
    after = keyed_tools(current)
    events: list[DriftEvent] = []
    for key in sorted(before.keys() | after.keys()):
        old = before.get(key)
        new = after.get(key)
        if old is None:
            events.append(_event(key, DriftField.TOOL_ADDED, None, new, now))
        elif new is None:
            events.append(_event(key, DriftField.TOOL_REMOVED, old, None, now))
        else:
            for field, attr in _PER_TOOL_FIELDS:
                if getattr(old, attr) != getattr(new, attr):
                    events.append(_event(key, field, old, new, now))
    return events


def compare_tools(
    baseline: ToolSnapshot,
    target: str,
    tools: Sequence[ToolRecord],
    *,
    now: datetime,
) -> tuple[DriftEvent, ...]:
    """Compare a stored baseline against a live listing."""
    current = ToolSnapshot.from_tools(target, tools, taken_at=now)
    return tuple(compare(baseline, current, now=now))
