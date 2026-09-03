from datetime import UTC, datetime

from agent_perimeter.db.models import CensusRecord
from agent_perimeter.report.census_report import (
    TERM_DEFINITIONS,
    aggregate,
    export_raw,
    render_census,
)
from tests.report.factories import census_fixture

# --- Brief's original 7 tests, adapted for the two-stratum shape ---------


def test_no_third_party_name_or_url_appears_in_the_report() -> None:
    run, records = census_fixture(names=["acme-mcp-server", "widget-tools"])
    html = render_census(run, records)
    for record in records:
        assert record.package_name is None or record.package_name not in html
        assert record.registry_id not in html


def test_the_word_vulnerable_is_never_used() -> None:
    run, records = census_fixture(probe_supports=3, probe_unknown=2)
    assert "vulnerable" not in render_census(run, records).lower()


def test_every_reported_term_is_defined() -> None:
    run, records = census_fixture()
    html = render_census(run, records)
    for term in ("population", "sample", "supports 2026-07-28", "unknown", "conformance gap"):
        assert term in TERM_DEFINITIONS
        assert TERM_DEFINITIONS[term] in html


def test_fetch_failures_appear_even_when_zero() -> None:
    run, records = census_fixture(fetch_failures=0)
    assert "Fetch failures: 0" in render_census(run, records)


def test_unknown_is_reported_separately_and_never_folded_into_a_denominator() -> None:
    run, records = census_fixture(unknown=12)
    agg = aggregate(records)["2026-07-28"]
    assert agg.unknown == 12
    assert agg.n == agg.supports + agg.does_not_support
    assert "12 unknown" in render_census(run, records)


def test_raw_export_is_keyed_by_digest_and_carries_no_names(tmp_path) -> None:  # type: ignore[no-untyped-def]
    run, records = census_fixture(names=["acme-mcp-server"])
    path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    body = path.read_text()
    assert "acme-mcp-server" not in body
    assert "coords_digest" in body


def test_the_report_states_the_tool_version_and_method_hash() -> None:
    run, records = census_fixture()
    html = render_census(run, records)
    assert run.method_hash in html and run.tool_version in html


# --- Two-stratum design: never pooled, honest empty state, per-ecosystem n --


def test_two_strata_render_as_separate_never_pooled_sections() -> None:
    """Artifact and live-discover are different populations measured by
    different methods. Neither headline number may combine them."""
    run, records = census_fixture(
        supports=3, does_not_support=1, unknown=0, probe_supports=4, probe_unknown=1
    )
    html = render_census(run, records)

    artifact_only = [r for r in records if r.feature_set_json.get("derivation") == "artifact"]
    probe_only = [r for r in records if r.feature_set_json.get("derivation") == "probe"]
    artifact_agg = aggregate(artifact_only)["2026-07-28"]
    probe_agg = aggregate(probe_only)["2026-07-28"]

    assert artifact_agg.supports == 3
    assert probe_agg.supports == 4

    # Both strata's own n appear, individually labelled.
    assert str(artifact_agg.n) in html
    assert str(probe_agg.n) in html

    # A blended total (pooling supports across both strata) is never stated.
    pooled_supports = artifact_agg.supports + probe_agg.supports
    assert f"{pooled_supports} of" not in html


def test_live_discover_stratum_honest_empty_state() -> None:
    """No Tier 3 data exists anywhere in this codebase yet - the report must
    say so plainly rather than rendering a broken '0 of 0' percentage."""
    run, records = census_fixture(probe_supports=0, probe_unknown=0)
    html = render_census(run, records)
    assert "not yet run" in html.lower()
    assert "0 of 0" not in html


def test_probe_stratum_never_reports_a_does_not_support_count() -> None:
    """A single unauthenticated server/discover request (census/tier3.py)
    can confirm support; it structurally cannot confirm absence - a
    non-answer is indistinguishable from a rejection by tier3's own design.
    """
    run, records = census_fixture(probe_supports=2, probe_unknown=5)
    probe_records = [r for r in records if r.feature_set_json.get("derivation") == "probe"]
    agg = aggregate(probe_records)["2026-07-28"]
    assert agg.does_not_support == 0
    assert agg.unknown == 5
    assert agg.supports == 2


def test_tier2_n_is_reported_per_ecosystem_not_pooled() -> None:
    """Task 5's correction: the registry's real ~29:1 npm:PyPI split means a
    single pooled tier-2 n misrepresents what was sampled from each
    ecosystem. Both ecosystem counts must appear, separately."""
    run, records = census_fixture(supports=4, does_not_support=2, unknown=0)
    html = render_census(run, records)
    assert "npm" in html
    assert "pypi" in html
    npm_n = sum(1 for r in records if r.ecosystem == "npm")
    pypi_n = sum(1 for r in records if r.ecosystem == "pypi")
    assert str(npm_n) in html
    assert str(pypi_n) in html


def test_the_word_vulnerable_never_appears_in_the_two_stratum_additions() -> None:
    run, records = census_fixture(probe_supports=0, probe_unknown=0)
    assert "vulnerable" not in render_census(run, records).lower()


def test_a_record_outside_both_strata_is_skipped_not_miscounted() -> None:
    """A tier-1-only entry, or an artifact fetch that failed before feature
    detection ever ran, carries no recognisable "derivation" tag. It must
    never be silently counted as "does not support" - it was never measured
    at all."""
    run, records = census_fixture(supports=1, does_not_support=0, unknown=0)
    stray = CensusRecord(
        census_run_id=run.id,
        registry_id="registry/never-attempted",
        coords_digest="stray-digest",
        ecosystem=None,
        package_name=None,
        distribution="none",
        sdk_version=None,
        feature_set_json={},
        fetch_status="not_attempted",
        fetch_detail=None,
        rank_metric=None,
        rank_metric_source=None,
        collected_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    agg = aggregate([*records, stray])["2026-07-28"]
    assert agg.supports == 1
    assert agg.does_not_support == 0
    assert agg.unknown == 0


def test_raw_export_carries_a_stratum_column_and_still_no_names(tmp_path) -> None:  # type: ignore[no-untyped-def]
    run, records = census_fixture(names=["acme-mcp-server"], probe_supports=1)
    path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    body = path.read_text()
    assert "stratum" in body
    assert "acme-mcp-server" not in body
    assert "registry/acme-mcp-server" not in body
