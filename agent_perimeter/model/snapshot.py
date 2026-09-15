"""A portable record of what a server's tools looked like at one moment.

This is the unit drift compares (spec §4.1). It is deliberately a plain
pydantic model with a version field: the CLI writes it to a file the
operator keeps between CI runs, the API rebuilds it from `tool` rows, and
both must produce byte-identical hashes for the same listing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from agent_perimeter.discover.enumerate import ToolRecord


def canonical_json(obj: object) -> str:
    """Sorted keys, no whitespace, unicode kept -- key order never counts as change."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    # The exact expression api/scans.py::_persist has written into
    # tool.description_hash since migration 0001 -- rows from before this
    # feature compare correctly against snapshots taken after it.
    return hashlib.sha256(text.encode()).hexdigest()


def sha256_json(obj: object) -> str:
    return sha256_text(canonical_json(obj))


class SnapshotTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    input_schema: dict[str, object]
    annotations: dict[str, object]
    description_hash: str
    schema_hash: str
    annotations_hash: str

    @classmethod
    def from_record(cls, record: ToolRecord) -> SnapshotTool:
        return cls(
            name=record.name,
            description=record.description,
            input_schema=record.input_schema,
            annotations=record.annotations,
            description_hash=sha256_text(record.description),
            schema_hash=sha256_json(record.input_schema),
            annotations_hash=sha256_json(record.annotations),
        )


class ToolSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: Literal[1] = 1
    target: str
    taken_at: datetime
    scan_id: str | None = None
    tools: list[SnapshotTool]

    @classmethod
    def from_tools(
        cls,
        target: str,
        tools: Sequence[ToolRecord],
        *,
        taken_at: datetime,
        scan_id: str | None = None,
    ) -> ToolSnapshot:
        return cls(
            target=target,
            taken_at=taken_at,
            scan_id=scan_id,
            tools=[SnapshotTool.from_record(record) for record in tools],
        )
