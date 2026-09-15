"""Schema shape after 0006: description text on tool; scan/baseline FKs and
nullable hashes on drift_event. Exercised through the ORM metadata so it
runs on sqlite; the Postgres upgrade/downgrade round-trip runs in the
clean-machine workflow and in Step 4 below when Docker is up."""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from agent_perimeter.db.models import Base, DriftEvent, Scan, Tool


def test_tool_has_a_nullable_description_and_drift_event_has_scan_fks(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    columns = {c["name"]: c for c in inspect(engine).get_columns("tool")}
    assert columns["description"]["nullable"] is True
    drift = {c["name"]: c for c in inspect(engine).get_columns("drift_event")}
    assert drift["scan_id"]["nullable"] is False
    assert drift["baseline_scan_id"]["nullable"] is False
    assert drift["old_hash"]["nullable"] is True
    assert drift["new_hash"]["nullable"] is True
    index_names = {i["name"] for i in inspect(engine).get_indexes("scan")}
    assert "ix_scan_target_finished" in index_names


def test_an_added_tool_event_persists_with_a_null_old_hash(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        base = Scan(target_ref="t", mode="passive", tool_version="0.1.0", finished_at=now)
        cur = Scan(target_ref="t", mode="passive", tool_version="0.1.0", finished_at=now)
        session.add_all([base, cur])
        session.flush()
        tool = Tool(scan_id=cur.id, name="new", description="Fresh.", description_hash="ab")
        session.add(tool)
        session.flush()
        session.add(
            DriftEvent(
                scan_id=cur.id,
                baseline_scan_id=base.id,
                tool_id=tool.id,
                field="tool_added",
                old_hash=None,
                new_hash="ab",
                severity="high",
            )
        )
        session.commit()
        [row] = session.query(DriftEvent).all()
        assert row.old_hash is None and row.scan_id == cur.id


def test_migration_0006_revises_0005() -> None:
    path = Path(__file__).parents[2] / "migrations" / "versions" / "0006_drift_text.py"
    spec = importlib.util.spec_from_file_location("m0006", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0006" and module.down_revision == "0005"
