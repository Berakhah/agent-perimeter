from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from agent_perimeter._contracts import SecretFingerprint
from agent_perimeter.checks.secrets.persist import record_secret_finding
from agent_perimeter.db.models import Base, Scan, SecretFinding


def test_record_secret_finding_writes_a_row() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
        session.add(scan)
        session.commit()

        fingerprint = SecretFingerprint.of(
            "sk-test-fakevaluefakevalue", location=".mcp.json:env.API_KEY"
        )
        row = record_secret_finding(session, scan_id=scan.id, fingerprint=fingerprint)

        assert row.id is not None
        assert row.expires_at is not None
        stored = session.execute(select(SecretFinding)).scalars().all()
        assert len(stored) == 1
        assert stored[0].scan_id == scan.id
        assert stored[0].fingerprint_sha256 == fingerprint.sha256
        assert stored[0].entropy == fingerprint.entropy
        assert stored[0].prefix == fingerprint.prefix
        assert stored[0].last4 == fingerprint.last4
        assert stored[0].location == fingerprint.location
    engine.dispose()


def test_record_secret_finding_never_marks_validated() -> None:
    # Hard constraint 3: a discovered secret is never validated against a
    # live service, and the schema enforces it with a CHECK constraint. This
    # write path must not be the one place that tries to set it anyway.
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
        session.add(scan)
        session.commit()

        fingerprint = SecretFingerprint.of("sk-test-anotherfakevalue", location="x")
        row = record_secret_finding(session, scan_id=scan.id, fingerprint=fingerprint)

        assert row.validated is False
    engine.dispose()
