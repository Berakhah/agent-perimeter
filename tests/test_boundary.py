import json

from agent_perimeter._contracts import SecretFingerprint

FAKE_KEY = "sk-test-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"


def test_fingerprint_never_serialises_the_raw_value() -> None:
    fp = SecretFingerprint.of(FAKE_KEY, location=".mcp.json:env.API_KEY")
    state = fp.__getstate__() if hasattr(fp, "__getstate__") else {}
    for rendering in (repr(fp), str(fp), json.dumps(state)):
        assert FAKE_KEY not in rendering


def test_fingerprint_has_no_attribute_holding_the_value() -> None:
    fp = SecretFingerprint.of(FAKE_KEY, location="x")
    for slot in SecretFingerprint.__slots__:
        assert FAKE_KEY not in str(getattr(fp, slot))


def test_secret_finding_row_cannot_record_validation() -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from agent_perimeter.db.models import Base, Scan, SecretFinding

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        scan = Scan(target_ref="t", mode="passive", tool_version="0.1.0")
        session.add(scan)
        session.commit()
        session.add(
            SecretFinding(
                scan_id=scan.id,
                fingerprint_sha256="a" * 64,
                entropy=4.2,
                prefix="sk-t",
                last4="O5p6",
                location="x",
                validated=True,
            )
        )
        try:
            session.commit()
        except IntegrityError:
            return
        raise AssertionError("a validated secret was persisted")
