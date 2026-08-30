"""Enumerate the tools a server exposes.

A server that will not list its tools is not an error condition — it is a
finding for `static/` to report. Enumeration returns what it got.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_perimeter.transport.base import Transport, TransportError


@dataclass(frozen=True)
class ToolRecord:
    name: str
    description: str
    input_schema: dict[str, object] = field(default_factory=dict)
    annotations: dict[str, object] = field(default_factory=dict)


def enumerate_tools(transport: Transport) -> list[ToolRecord]:
    try:
        listing = transport.request("tools/list")
    except TransportError:
        return []

    raw_tools = listing.get("tools")
    if not isinstance(raw_tools, list):
        return []

    records: list[ToolRecord] = []
    for entry in raw_tools:
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        schema = entry.get("inputSchema")
        annotations = entry.get("annotations")
        records.append(
            ToolRecord(
                name=str(entry["name"]),
                description=str(entry.get("description", "")),
                input_schema=schema if isinstance(schema, dict) else {},
                annotations=annotations if isinstance(annotations, dict) else {},
            )
        )
    return records
