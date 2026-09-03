from agent_perimeter.db.models import CensusRecord, CensusRun


def test_census_run_records_failures_and_method() -> None:
    cols = {c.name for c in CensusRun.__table__.columns}
    assert {"population_size", "fetch_failures", "tool_version", "method_hash"} <= cols


def test_census_record_has_no_column_that_could_hold_a_secret() -> None:
    forbidden = {"token", "secret", "password", "api_key", "credential"}
    for col in CensusRecord.__table__.columns:
        assert not any(f in col.name.lower() for f in forbidden)


def test_coords_digest_is_not_nullable() -> None:
    assert CensusRecord.__table__.c.coords_digest.nullable is False


def test_census_record_has_a_distribution_column() -> None:
    cols = {c.name for c in CensusRecord.__table__.columns}
    assert "distribution" in cols
