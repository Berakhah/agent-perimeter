from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
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
            scan_id=scan.id, fingerprint_sha256="a" * 64, entropy=4.2, prefix="sk-t",
            last4="0001", location="x", expires_at=datetime.now(UTC) - timedelta(days=1),
        )
        current = SecretFinding(
            scan_id=scan.id, fingerprint_sha256="b" * 64, entropy=4.2, prefix="sk-t",
            last4="0002", location="y", expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        session.add_all([expired, current])
        session.commit()

        deleted = purge_expired_secrets(session)
        assert deleted == 1

        remaining = session.execute(select(SecretFinding)).scalars().all()
        assert [r.last4 for r in remaining] == ["0002"]
    engine.dispose()
