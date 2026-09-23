from datetime import UTC, datetime

from agent_perimeter.db.models import CensusRecord
from agent_perimeter.report.census_report import (
    TERM_DEFINITIONS,
    Aggregate,
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
    """No live-discover data exists anywhere in this codebase - the module
    that would have produced it (census/tier3.py) was removed after code
    review found it sent unauthorised active probes with no ScopeFile gate
    (docs/census/CHANGELOG.md, docs/open-decisions.md decision 5) - so the
    report must say so plainly rather than rendering a broken '0 of 0'
    percentage."""
    run, records = census_fixture(probe_supports=0, probe_unknown=0)
    html = render_census(run, records)
    assert "not run" in html.lower()
    assert "0 of 0" not in html


def test_probe_stratum_never_reports_a_does_not_support_count() -> None:
    """A single unauthenticated server/discover request (the design the now-
    removed census/tier3.py used) can confirm support; it structurally
    cannot confirm absence - a non-answer is indistinguishable from a
    rejection.
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


# --- Review fixes ----------------------------------------------------------


def test_embedded_stylesheet_is_not_html_escaped() -> None:
    """report.css's `font-family: "IBM Plex Mono", ...` and the print-mode
    `content: attr(data-glyph) " ";` rules are the no-colour-only-encoding
    mechanism this task was required to reuse from Week 3. Jinja's default
    autoescape turns every `"` into `&#34;`, which is invalid inside a
    <style> block and would silently break both rules. The stylesheet must
    reach the page unescaped."""
    run, records = census_fixture()
    html = render_census(run, records)
    assert '"IBM Plex Mono"' in html
    style_block = html.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "&#34;" not in style_block
    assert "&quot;" not in style_block


def test_probe_stratum_never_renders_a_bare_percentage() -> None:
    """does_not_support is structurally always 0 for this stratum, so a
    naive supports/n share would read 100% even when most of the sample
    never answered at all - e.g. 2 supports against 5 non-responses. The
    live-discover section must never state a percentage; it must state the
    non-response count instead."""
    run, records = census_fixture(probe_supports=2, probe_unknown=5)
    html = render_census(run, records)

    section = html.split("<h2>Live-discover stratum</h2>", 1)[1].split("<h2>", 1)[0]
    assert "%" not in section
    assert "5" in section and "7" in section  # unknown / sampled counts, stated as raw numbers
    assert "non-response" in section.lower()


# --- Task 7: tier 2 is a seeded random draw, and the seed is published ------


def test_the_report_and_summary_state_the_sample_seed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A seeded draw is only reproducible if the seed is published with it:
    the rendered report and the raw-data sidecar must both carry it."""
    import json

    run, records = census_fixture(sample_seed=8675309)
    html = render_census(run, records)
    assert 'data-testid="sample-seed">8675309<' in html
    assert "seed 8675309" in html
    assert "download count" not in html.lower()

    export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary = json.loads((tmp_path / "records.summary.json").read_text(encoding="utf-8"))
    assert summary["sample_seed"] == 8675309


# --- First-publication review fixes: headline order, unknown definition, ----
# --- sample description (distribution, failure split), limitations, shares --


def _record(
    run_id: int,
    *,
    name: str,
    ecosystem: str | None,
    distribution: str,
    fetch_status: str = "ok",
    fetch_detail: str | None = "",
    sdk_version: str | None = None,
    features: list[str] | None = None,
    caveat: str | None = None,
    derivation: str | None = "artifact",
    is_unknown: bool = False,
) -> CensusRecord:
    fs: dict[str, object] = {}
    if derivation is not None:
        fs = {
            "features": features or [],
            "derivation": derivation,
            "confidence": 0.6,
            "caveat": caveat,
            "is_unknown": is_unknown,
        }
    return CensusRecord(
        census_run_id=run_id,
        registry_id=f"registry/{name}",
        coords_digest=f"digest-{name}",
        ecosystem=ecosystem,
        package_name=name if ecosystem else None,
        distribution=distribution,
        sdk_version=sdk_version,
        feature_set_json=fs,
        fetch_status=fetch_status,
        fetch_detail=fetch_detail,
        rank_metric=None,
        rank_metric_source=None,
        collected_at=datetime(2026, 9, 1, tzinfo=UTC),
    )


def _headline(html: str) -> str:
    return html.split("<h2>Headline</h2>", 1)[1].split("<h2>", 1)[0]


def test_headline_leads_per_ecosystem_and_labels_the_pooled_figure_second() -> None:
    """The artifact headline must state npm and PyPI separately first; the
    pooled figure may follow only when labelled as pooled, for reference."""
    # idx%2 split: npm gets idx 0,2 (supports) + 4 (dns) = 2 of 3;
    # pypi gets idx 1 (supports) + 3 (dns) = 1 of 2; pooled 3 of 5.
    run, records = census_fixture(supports=3, does_not_support=2, unknown=0)
    head = _headline(render_census(run, records))
    npm_at = head.index("npm")
    pypi_at = head.index("PyPI")
    pooled_at = head.lower().index("pooled")
    assert npm_at < pooled_at and pypi_at < pooled_at
    assert "2 of 3" in head and "1 of 2" in head
    assert "3 of 5" in head
    assert head.index("3 of 5") > pooled_at
    assert "for reference" in head.lower()


def test_unknown_definition_matches_the_arithmetic() -> None:
    """Fetch failures never enter n_examined, so they cannot be 'unknown':
    unknown means fetched and extracted, but no SDK pin and no parseable
    source. The definition must say exactly that."""
    definition = TERM_DEFINITIONS["unknown"].lower()
    assert "could not be fetched" not in definition
    assert "fetched and extracted" in definition
    assert "no sdk pin" in definition and "no parseable source" in definition
    assert "fetch failures" in definition and "separately" in definition


def test_report_and_summary_carry_the_population_distribution(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    run, records = census_fixture(supports=2, does_not_support=1, unknown=1)
    rid = run.id
    assert rid is not None
    records += [
        _record(
            rid,
            name=f"remote-{i}",
            ecosystem=None,
            distribution="remote_only",
            fetch_status="not_attempted",
            derivation=None,
        )
        for i in range(3)
    ]
    records.append(
        _record(
            rid,
            name="bare",
            ecosystem=None,
            distribution="none",
            fetch_status="not_attempted",
            derivation=None,
        )
    )
    records.append(
        _record(
            rid,
            name="oci-thing",
            ecosystem=None,
            distribution="package_other",
            fetch_status="not_attempted",
            derivation=None,
        )
    )
    html = render_census(run, records)
    assert 'data-testid="distribution-remote_only">3<' in html
    assert 'data-testid="distribution-package_npm">2<' in html
    assert 'data-testid="distribution-package_pypi">2<' in html
    assert 'data-testid="distribution-package_other">1<' in html
    assert 'data-testid="distribution-none">1<' in html
    # Scope sentence names the npm+PyPI frame (final-review item 3), not "packaged".
    assert "npm or PyPI package coordinates" in html
    assert 'data-testid="eligible-count">4<' in html  # 2 npm + 2 pypi, package_other excluded

    export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary = json.loads((tmp_path / "records.summary.json").read_text(encoding="utf-8"))
    assert summary["population"]["size"] == run.population_size
    assert summary["population"]["distribution"] == {
        "remote_only": 3,
        "package_npm": 2,
        "package_pypi": 2,
        "package_other": 1,
        "none": 1,
    }


def test_fetch_failures_are_split_and_bucketed_never_verbatim(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Registry-pagination vs artifact failures, and a per-cause breakdown by
    fixed label. `fetch_detail` may carry a package name, so it is bucketed by
    prefix and never printed."""
    import json

    run, records = census_fixture(supports=1, does_not_support=0, unknown=0, fetch_failures=5)
    rid = run.id
    assert rid is not None
    records += [
        _record(
            rid,
            name="acme-secret-pkg",
            ecosystem="pypi",
            distribution="package_pypi",
            fetch_status="not_found",
            derivation=None,
            fetch_detail="no downloadable artifact for acme-secret-pkg (latest)",
        ),
        _record(
            rid,
            name="acme-other-pkg",
            ecosystem="npm",
            distribution="package_npm",
            fetch_status="not_found",
            derivation=None,
            fetch_detail="package not found: acme-other-pkg",
        ),
        _record(
            rid,
            name="acme-big-pkg",
            ecosystem="npm",
            distribution="package_npm",
            fetch_status="parse_error",
            derivation=None,
            fetch_detail="archive rejected: member exceeds 33554432 bytes: package/evil-name.js",
        ),
    ]
    html = render_census(run, records)
    for secret in ("acme-secret-pkg", "acme-other-pkg", "acme-big-pkg", "evil-name"):
        assert secret not in html
    assert 'data-testid="fetch-failures-registry">2<' in html
    assert 'data-testid="fetch-failures-artifact">3<' in html
    assert "no downloadable artifact" in html
    assert "package not found" in html
    assert "member exceeds the per-file size cap" in html

    export_raw(run, records, salt=b"test-salt", out=tmp_path)
    body = (tmp_path / "records.summary.json").read_text(encoding="utf-8")
    for secret in ("acme-secret-pkg", "acme-other-pkg", "acme-big-pkg", "evil-name"):
        assert secret not in body
    summary = json.loads(body)
    ff = summary["fetch_failures"]
    assert ff == {
        "total": 5,
        "registry_pagination": 2,
        "artifact": 3,
        "by_cause": {
            "no downloadable artifact": 1,
            "package not found": 1,
            "archive rejected: member exceeds the per-file size cap": 1,
        },
        "by_ecosystem_status": {
            "npm": {"ok": 1, "not_found": 1, "parse_error": 1},
            "pypi": {"not_found": 1},
        },
    }


def test_detection_limitations_are_stated_with_counts(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Two known under-counts of the two-signals rule must be stated with
    their per-ecosystem counts: pinned at/above the floor but no handler
    string in shipped source, and source signal dropped because the pin
    predates the floor."""
    import json

    run, records = census_fixture(supports=0, does_not_support=0, unknown=0)
    rid = run.id
    assert rid is not None
    records += [
        _record(rid, name="a", ecosystem="npm", distribution="package_npm", sdk_version="2.0.0"),
        _record(rid, name="b", ecosystem="pypi", distribution="package_pypi", sdk_version="2.1.0"),
        _record(rid, name="c", ecosystem="pypi", distribution="package_pypi", sdk_version="2.3.0"),
        _record(
            rid,
            name="d",
            ecosystem="pypi",
            distribution="package_pypi",
            sdk_version="1.9.0",
            caveat="source mentions server_discover but the sdk pin (1.9.0) predates it; "
            "sdk pin wins",
        ),
        _record(rid, name="e", ecosystem="npm", distribution="package_npm", sdk_version="1.2.0"),
        _record(
            rid,
            name="f",
            ecosystem="npm",
            distribution="package_npm",
            sdk_version="2.0.0",
            features=["server_discover"],
        ),
        # Handler string but no pin at all: reported unknown (final-review
        # item 2), so it is not a does-not-support under-count and must not
        # be counted as a floor-dropped signal.
        _record(
            rid,
            name="g",
            ecosystem="pypi",
            distribution="package_pypi",
            sdk_version=None,
            is_unknown=True,
            caveat="source mentions server_discover but the artifact pins no SDK; a feature "
            "cannot be asserted without a pin at or above its floor",
        ),
    ]
    html = render_census(run, records)
    assert 'data-testid="pinned-without-handler-npm">1<' in html
    assert 'data-testid="pinned-without-handler-pypi">2<' in html
    assert 'data-testid="pinned-without-handler-total">3<' in html
    assert 'data-testid="floor-dropped-total">1<' in html
    assert "limitation" in html.lower()

    export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary = json.loads((tmp_path / "records.summary.json").read_text(encoding="utf-8"))
    assert summary["limitations"] == {
        "pinned_at_floor_without_handler": {"npm": 1, "pypi": 2, "total": 3},
        "floor_dropped_source_signal": {"npm": 0, "pypi": 1, "total": 1},
    }


def test_shares_render_to_one_decimal() -> None:
    # npm: idx0 supports, idx2 dns -> 1 of 2 = 50.0%; pypi: idx1 dns -> 0.0%; pooled 1/3 = 33.3%.
    run, records = census_fixture(supports=1, does_not_support=2, unknown=0)
    html = render_census(run, records)
    assert "50.0%" in html and "0.0%" in html and "33.3%" in html


# --- Final review: the scope sentence counts npm+PyPI only, and every share
# --- carries a Wilson 95% interval.


def test_scope_sentence_counts_only_npm_and_pypi_as_eligible() -> None:
    """`package_other` is not modelled, so it cannot be inside the frame Tier 2
    samples from. The count in the scope sentence must exclude it."""
    run, records = census_fixture(supports=2, does_not_support=1, unknown=1)
    rid = run.id
    assert rid is not None
    records += [
        _record(
            rid,
            name=f"oci-{i}",
            ecosystem=None,
            distribution="package_other",
            fetch_status="not_attempted",
            derivation=None,
        )
        for i in range(3)
    ]
    html = render_census(run, records)
    assert 'data-testid="eligible-count">4<' in html
    assert 'data-testid="package-other-count">3<' in html
    assert "not eligible" in html


def test_wilson_interval_matches_the_published_formula() -> None:
    """Standard Wilson score interval, z = 1.959964. For 3 of 176 the
    textbook value is (0.0058, 0.0489); the review note's 0.0036 lower bound
    does not come from the Wilson formula at this n."""
    agg = Aggregate(supports=3, does_not_support=173, unknown=0)
    ci = agg.wilson95
    assert ci is not None
    lo, hi = ci
    assert abs(lo - 0.0058) < 1e-3
    assert abs(hi - 0.0489) < 1e-3
    assert Aggregate(supports=0, does_not_support=0, unknown=5).wilson95 is None
    # Bounds never leave [0, 1]; a zero count still gets a positive upper bound.
    zero = Aggregate(supports=0, does_not_support=10, unknown=0).wilson95
    assert zero is not None and zero[0] == 0.0 and 0.0 < zero[1] < 0.35


def test_shares_render_with_a_wilson_interval_and_the_summary_carries_it(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import json

    # npm: idx0 supports, idx2 dns -> 1 of 2; pypi: idx1 dns -> 0 of 1; pooled 1 of 3.
    run, records = census_fixture(supports=1, does_not_support=2, unknown=0)
    html = render_census(run, records)
    assert "50.0% (95% CI 9.5–90.5%)" in html
    assert "33.3% (95% CI 6.1–79.2%)" in html

    export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary = json.loads((tmp_path / "records.summary.json").read_text(encoding="utf-8"))
    npm = summary["artifact"]["by_ecosystem"]["npm"]
    assert npm["share"] == 0.5
    assert abs(npm["wilson95"][0] - 0.0945) < 1e-3
    assert abs(npm["wilson95"][1] - 0.9055) < 1e-3
    assert summary["artifact"]["pooled"]["wilson95"] is not None
    assert summary["live_discover"] is None
