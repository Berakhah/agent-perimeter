"""Schema shape after 0007: an explicit `position` on tool, so a scan's
listing order is stored rather than reconstructed from (first_seen_at, id)
-- which mispairs duplicate-named copies when their timestamps collide."""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from agent_perimeter.api.drift import snapshot_from_scan
from agent_perimeter.db.models import Base, Scan, Tool


def test_tool_has_a_not_null_position(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    columns = {c["name"]: c for c in inspect(engine).get_columns("tool")}
    assert columns["position"]["nullable"] is False
    engine.dispose()


def test_snapshot_from_scan_orders_by_position_not_by_timestamp_or_id(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0", finished_at=now)
        session.add(scan)
        session.flush()
        # Same timestamp; the id that sorts FIRST is the SECOND listing entry.
        session.add_all(
            [
                Tool(
                    id="a",
                    scan_id=scan.id,
                    name="x",
                    description="two",
                    description_hash="2",
                    first_seen_at=now,
                    position=2,
                ),
                Tool(
                    id="b",
                    scan_id=scan.id,
                    name="x",
                    description="one",
                    description_hash="1",
                    first_seen_at=now,
                    position=1,
                ),
            ]
        )
        session.commit()
        snapshot = snapshot_from_scan(session, scan)
    assert [t.description for t in snapshot.tools] == ["one", "two"]
    engine.dispose()


def test_migration_0007_revises_0006() -> None:
    path = Path(__file__).parents[2] / "migrations" / "versions" / "0007_tool_position.py"
    spec = importlib.util.spec_from_file_location("m0007", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0007" and module.down_revision == "0006"
