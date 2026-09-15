"""ToolSnapshot is the unit drift compares. Hashes must be canonical:
key order never counts as change, and description_hash must equal the
expression api/scans.py::_persist has written since 0001."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.snapshot import (
    SnapshotTool,
    ToolSnapshot,
    canonical_json,
    sha256_json,
    sha256_text,
)

TAKEN = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def test_canonical_json_sorts_keys_and_strips_whitespace() -> None:
    assert canonical_json({"b": 1, "a": [1, {"z": 0, "y": 1}]}) == '{"a":[1,{"y":1,"z":0}],"b":1}'


def test_sha256_json_is_order_independent() -> None:
    assert sha256_json({"a": 1, "b": 2}) == sha256_json({"b": 2, "a": 1})


def test_description_hash_matches_the_persisted_expression() -> None:
    record = ToolRecord(name="read_file", description="Read a file.")
    tool = SnapshotTool.from_record(record)
    assert tool.description_hash == hashlib.sha256(b"Read a file.").hexdigest()
    assert tool.description_hash == sha256_text("Read a file.")


def test_from_tools_keeps_listing_order_and_carries_target_and_time() -> None:
    records = [ToolRecord(name="b", description="B"), ToolRecord(name="a", description="A")]
    snap = ToolSnapshot.from_tools("https://mcp.example.test", records, taken_at=TAKEN)
    assert snap.version == 1
    assert snap.target == "https://mcp.example.test"
    assert snap.taken_at == TAKEN
    assert snap.scan_id is None
    assert [t.name for t in snap.tools] == ["b", "a"]


def test_snapshot_round_trips_through_json() -> None:
    snap = ToolSnapshot.from_tools(
        "t", [ToolRecord(name="x", description="dé", input_schema={"k": 1})], taken_at=TAKEN
    )
    again = ToolSnapshot.model_validate_json(snap.model_dump_json())
    assert again == snap


def test_unknown_version_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolSnapshot.model_validate({"version": 2, "target": "t", "taken_at": TAKEN, "tools": []})
