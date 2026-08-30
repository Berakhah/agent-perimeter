from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, insert, select
from sqlalchemy.orm import Session

from agent_perimeter.checks.secrets.purge import purge_expired_secrets
from agent_perimeter.db.models import Base, Scan, SecretFinding


def test_purge_deletes_expired_rows_and_keeps_current_ones() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
        session.add(scan)
        session.commit()

        expired = SecretFinding(
            scan_id=scan.id,
            fingerprint_sha256="a" * 64,
            entropy=4.2,
            prefix="sk-t",
            last4="0001",
            location="x",
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        current = SecretFinding(
            scan_id=scan.id,
            fingerprint_sha256="b" * 64,
            entropy=4.2,
            prefix="sk-t",
            last4="0002",
            location="y",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        session.add_all([expired, current])
        session.commit()

        deleted = purge_expired_secrets(session)
        assert deleted == 1

        remaining = session.execute(select(SecretFinding)).scalars().all()
        assert [r.last4 for r in remaining] == ["0002"]
    engine.dispose()


def test_purge_also_deletes_rows_with_no_recorded_expiry() -> None:
    # The migration added expires_at as nullable (no backfill for rows that
    # predate it). A NULL expiry shouldn't let a fingerprint accumulate
    # forever either — consistent with B4's bounded-retention intent.
    #
    # A real NULL row only exists pre-migration (ALTER TABLE ADD COLUMN sets
    # NULL for existing rows, no backfill) — the ORM's own Python-side
    # `default=` on SecretFinding.expires_at fires whenever the attribute
    # reads as None, so constructing SecretFinding(expires_at=None) through
    # the ORM does NOT produce a NULL row (verified: it silently gets the
    # 90-day default instead). A Core-level insert bypasses that and matches
    # the real scenario.
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
        session.add(scan)
        session.commit()

        session.execute(
            insert(SecretFinding.__table__).values(
                id="row-no-expiry",
                scan_id=scan.id,
                fingerprint_sha256="c" * 64,
                entropy=4.2,
                prefix="sk-t",
                last4="0003",
                location="z",
                validated=False,
                expires_at=None,
            )
        )
        current = SecretFinding(
            scan_id=scan.id,
            fingerprint_sha256="d" * 64,
            entropy=4.2,
            prefix="sk-t",
            last4="0004",
            location="w",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        session.add(current)
        session.commit()

        deleted = purge_expired_secrets(session)
        assert deleted == 1

        remaining = session.execute(select(SecretFinding)).scalars().all()
        assert [r.last4 for r in remaining] == ["0004"]
    engine.dispose()
