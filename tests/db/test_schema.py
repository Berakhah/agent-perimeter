# tests/db/test_schema.py
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agent_perimeter.db.models import Base, Scan, SecretFinding


@event.listens_for(Engine, "connect")
def _enable_sqlite_constraints(dbapi_connection: object, _: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def test_scan_records_claimed_and_observed_revision_separately(session: Session) -> None:
    scan = Scan(
        target_ref="https://mcp.example.test",
        mode="passive",
        tool_version="0.1.0",
        revision_claimed="2026-07-28",
        revision_observed="2025-11-25",
        feature_set_json=["server_discover"],
    )
    session.add(scan)
    session.commit()
    assert scan.revision_claimed != scan.revision_observed


def test_secret_finding_cannot_be_marked_validated(session: Session) -> None:
    scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
    session.add(scan)
    session.commit()

    session.add(
        SecretFinding(
            scan_id=scan.id,
            fingerprint_sha256="a" * 64,
            entropy=4.2,
            prefix="synthetic_",
            last4="wxyz",
            location=".mcp.json:12",
            validated=True,
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()


def test_secret_finding_has_no_column_for_a_raw_value() -> None:
    columns = {c.name for c in SecretFinding.__table__.columns}
    for forbidden in ("value", "secret", "raw", "token", "plaintext"):
        assert forbidden not in columns, f"{forbidden} column could hold a raw secret"


def test_never_validated_constraint_is_present_in_ddl() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        ddl = conn.execute(
            text("SELECT sql FROM sqlite_master WHERE name='secret_finding'")
        ).scalar_one()
    engine.dispose()
    assert "ck_secret_finding_never_validated" in ddl
