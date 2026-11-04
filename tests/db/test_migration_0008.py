"""Schema shape after 0008: scan.listing_complete, NOT NULL, default true,
so a scan whose tools/list stopped early can be kept out of baseline
selection while every row already on record stays a valid baseline."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect, text

from agent_perimeter.db.models import Base

MIGRATION = Path(__file__).parents[2] / "migrations" / "versions" / "0008_scan_listing_complete.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("m0008", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_0008_revises_0007() -> None:
    module = _load()
    assert module.revision == "0008" and module.down_revision == "0007"


def test_orm_scan_has_a_not_null_listing_complete(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    Base.metadata.create_all(engine)
    columns = {c["name"]: c for c in inspect(engine).get_columns("scan")}
    assert columns["listing_complete"]["nullable"] is False
    engine.dispose()


def test_upgrade_backfills_existing_rows_as_complete_and_downgrade_drops_it(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE scan (id VARCHAR(36) PRIMARY KEY, target_ref TEXT)"))
        conn.execute(text("INSERT INTO scan (id, target_ref) VALUES ('old', 't')"))
        module = _load()
        module.op = Operations(MigrationContext.configure(conn))
        module.upgrade()
        assert conn.execute(text("SELECT listing_complete FROM scan")).scalar_one() == 1
        conn.execute(text("INSERT INTO scan (id, target_ref) VALUES ('new', 't')"))
        assert (
            conn.execute(text("SELECT listing_complete FROM scan WHERE id = 'new'")).scalar_one()
            == 1
        )
        module.downgrade()
        columns = {c["name"] for c in inspect(conn).get_columns("scan")}
        assert "listing_complete" not in columns
    engine.dispose()
