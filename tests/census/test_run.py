"""Tests for census orchestration: method_hash, run_census, temp-dir cleanup,
and distribution-column population.

Registry pagination and tier-2 ranking go through a single httpx.MockTransport
dispatched by host, mirroring the real hosts fetch.py/sample.py talk to.
`artifacts.fetch_artifact` is monkeypatched to isolate orchestration
(the cleanup guarantee, fetch_status/failure bookkeeping, distribution) from
archive-download/extraction mechanics already covered by test_artifacts.py;
`detect.detect_features` runs for real against a small on-disk tree so the
sdk_version/feature_set_json wiring is exercised end to end.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from agent_perimeter.census.run import method_hash, run_census
from agent_perimeter.db.models import Base, CensusRecord, CensusRun
from agent_perimeter.model.census import FetchStatus

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"


def _server_item(
    name: str,
    *,
    version: str = "1.0.0",
    packages: list[dict[str, object]] | None = None,
    remotes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    server: dict[str, object] = {"name": name, "version": version}
    if packages is not None:
        server["packages"] = packages
    if remotes is not None:
        server["remotes"] = remotes
    return {"server": server}


def _page(items: list[dict[str, object]], *, next_cursor: str | None = None) -> dict[str, object]:
    metadata: dict[str, object] = {} if next_cursor is None else {"nextCursor": next_cursor}
    return {"servers": items, "metadata": metadata}


def _handler(
    pages: dict[str | None, dict[str, object]],
    downloads: dict[tuple[str, str], int],
) -> Callable[[httpx.Request], httpx.Response]:
    """Dispatch by host: registry pagination (keyed by cursor) and the two
    download-count endpoints rank() calls for every entry with coords."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "registry.modelcontextprotocol.io":
            cursor = request.url.params.get("cursor")
            page = pages.get(cursor)
            if page is None:
                return httpx.Response(500)
            return httpx.Response(200, json=page)
        if host == "pypistats.org":
            name = request.url.path.split("/")[3]
            count = downloads.get(("pypi", name))
            if count is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"data": {"last_month": count}})
        if host == "api.npmjs.org":
            name = request.url.path.rsplit("/", 1)[-1]
            count = downloads.get(("npm", name))
            if count is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"downloads": count})
        raise AssertionError(f"unexpected host in test: {host}")

    return handler


def _engine() -> Engine:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine


# --- method_hash ---------------------------------------------------------


def test_method_hash_is_a_stable_hex_string() -> None:
    a = method_hash()
    b = method_hash()
    assert a == b
    assert len(a) == 16
    int(a, 16)  # raises ValueError if not hex


# --- run_census: basic orchestration --------------------------------------


def test_run_census_persists_a_run_with_the_right_summary_fields() -> None:
    items = [_server_item("pkg/bare-one")]
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, {})))
    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)

        assert run.id is not None
        assert run.population_size == 1
        assert run.tier2_n == 5
        assert run.registry_endpoint == REGISTRY
        assert run.method_hash == method_hash()
        assert run.tool_version
        assert run.started_at is not None
        assert run.finished_at is not None
        assert run.started_at <= run.finished_at
        assert run.fetch_failures == 0

        stored = session.execute(select(CensusRun).where(CensusRun.id == run.id)).scalar_one()
        assert stored.population_size == 1
    engine.dispose()


def test_run_census_paginates_across_multiple_pages() -> None:
    page1 = _page([_server_item("pkg/one")], next_cursor="c2")
    page2 = _page([_server_item("pkg/two")])
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: page1, "c2": page2}, {})))
    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)
        assert run.population_size == 2
    engine.dispose()


# --- distribution column ---------------------------------------------------


def test_distribution_is_populated_for_every_case() -> None:
    items = [
        _server_item(
            "pkg/npm-one",
            packages=[{"registryType": "npm", "identifier": "npm-one", "version": "1.0.0"}],
        ),
        _server_item(
            "pkg/pypi-one",
            packages=[{"registryType": "pypi", "identifier": "pypi-one", "version": "1.0.0"}],
        ),
        _server_item(
            "pkg/oci-one",
            packages=[{"registryType": "oci", "identifier": "oci-one", "version": "1.0.0"}],
        ),
        _server_item("pkg/remote-one", remotes=[{"url": "https://example.invalid/mcp"}]),
        _server_item("pkg/bare-one"),
    ]
    downloads = {("npm", "npm-one"): 100, ("pypi", "pypi-one"): 50}
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, downloads)))
    engine = _engine()
    with Session(engine) as session:
        # tier2_n=0: no artifact fetch is attempted for anyone, isolating the
        # distribution assertion below from artifact-fetch mechanics.
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=0)
        records = (
            session.execute(select(CensusRecord).where(CensusRecord.census_run_id == run.id))
            .scalars()
            .all()
        )
    engine.dispose()

    by_id = {r.registry_id: r for r in records}
    assert by_id["pkg/npm-one:1.0.0"].distribution == "package_npm"
    assert by_id["pkg/pypi-one:1.0.0"].distribution == "package_pypi"
    assert by_id["pkg/oci-one:1.0.0"].distribution == "package_other"
    assert by_id["pkg/remote-one:1.0.0"].distribution == "remote_only"
    assert by_id["pkg/bare-one:1.0.0"].distribution == "none"

    # Nothing was attempted (tier2_n=0): every record says so explicitly
    # rather than defaulting to a FetchStatus value that would falsely imply
    # a network call was made.
    assert all(r.fetch_status == "not_attempted" for r in records)

    # coords_digest is non-null and set even for entries with no PackageCoords
    # at all (remote-only, bare) - the pseudonym has to cover every record,
    # not just the ones with a package.
    assert all(r.coords_digest for r in records)
    assert by_id["pkg/npm-one:1.0.0"].rank_metric == 100
    assert by_id["pkg/pypi-one:1.0.0"].rank_metric == 50
    assert by_id["pkg/bare-one:1.0.0"].rank_metric is None


# --- temp-dir cleanup -------------------------------------------------------


def test_temp_dir_is_removed_after_a_successful_tier2_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Task 3's fetch_artifact leaves ArtifactResult.root caller-owned. run_census
    is the caller: it must delete the extracted temp dir once detect_features
    has read it, or a real census leaks up to 256 MiB per package for the
    run's lifetime.
    """
    extracted_root = tmp_path / "extracted"
    extracted_root.mkdir()
    (extracted_root / "pyproject.toml").write_text(
        '[project]\ndependencies = ["mcp==2.0.0"]\n', encoding="utf-8"
    )

    items = [
        _server_item(
            "pkg/npm-one",
            packages=[{"registryType": "npm", "identifier": "npm-one", "version": "1.0.0"}],
        )
    ]
    downloads = {("npm", "npm-one"): 999}
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, downloads)))

    from agent_perimeter.census.artifacts import ArtifactResult

    def fake_fetch_artifact(client: httpx.Client, coords: object) -> ArtifactResult:
        return ArtifactResult(
            status=FetchStatus.OK, detail="", root=extracted_root, version="1.0.0"
        )

    monkeypatch.setattr("agent_perimeter.census.artifacts.fetch_artifact", fake_fetch_artifact)

    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)
        records = (
            session.execute(select(CensusRecord).where(CensusRecord.census_run_id == run.id))
            .scalars()
            .all()
        )
    engine.dispose()

    assert not extracted_root.exists()
    assert records[0].fetch_status == FetchStatus.OK.value
    assert records[0].sdk_version == "2.0.0"


def test_temp_dir_is_removed_even_when_no_source_features_are_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same cleanup guarantee when detect_features finds nothing to report -
    cleanup must not be conditioned on a successful detection."""
    extracted_root = tmp_path / "extracted-empty"
    extracted_root.mkdir()

    items = [
        _server_item(
            "pkg/npm-two",
            packages=[{"registryType": "npm", "identifier": "npm-two", "version": "1.0.0"}],
        )
    ]
    downloads = {("npm", "npm-two"): 5}
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, downloads)))

    from agent_perimeter.census.artifacts import ArtifactResult

    def fake_fetch_artifact(client: httpx.Client, coords: object) -> ArtifactResult:
        return ArtifactResult(
            status=FetchStatus.OK, detail="", root=extracted_root, version="1.0.0"
        )

    monkeypatch.setattr("agent_perimeter.census.artifacts.fetch_artifact", fake_fetch_artifact)

    engine = _engine()
    with Session(engine) as session:
        run_census(session, client, endpoint=REGISTRY, tier2_n=5)
    engine.dispose()

    assert not extracted_root.exists()


# --- fetch_failures aggregation ---------------------------------------------


def test_fetch_failures_counts_artifact_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    items = [
        _server_item(
            "pkg/npm-one",
            packages=[{"registryType": "npm", "identifier": "npm-one", "version": "1.0.0"}],
        )
    ]
    downloads = {("npm", "npm-one"): 10}
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, downloads)))

    from agent_perimeter.census.artifacts import ArtifactResult

    def failing_fetch_artifact(client: httpx.Client, coords: object) -> ArtifactResult:
        return ArtifactResult(
            status=FetchStatus.NOT_FOUND, detail="no artifact", root=None, version=None
        )

    monkeypatch.setattr("agent_perimeter.census.artifacts.fetch_artifact", failing_fetch_artifact)

    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)
        records = (
            session.execute(select(CensusRecord).where(CensusRecord.census_run_id == run.id))
            .scalars()
            .all()
        )
    engine.dispose()

    assert run.fetch_failures == 1
    assert records[0].fetch_status == FetchStatus.NOT_FOUND.value


def test_a_truncated_pagination_aborts_the_run_and_commits_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before Task 6 this scenario produced a committed CensusRun with
    population_size == 1 and fetch_failures == 1: a prefix published as a
    population. Now the read fails loudly and no row survives the session."""
    from agent_perimeter.census import fetch

    monkeypatch.setattr(fetch.time, "sleep", lambda _s: None)
    items = [_server_item("pkg/bare-one")]
    # page 1 points at a cursor whose page the handler doesn't have -> the
    # handler's 500 branch fires on every retry.
    page1 = _page(items, next_cursor="missing")
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: page1}, {})))

    engine = _engine()
    with Session(engine) as session, pytest.raises(fetch.PaginationTruncated) as excinfo:
        run_census(session, client, endpoint=REGISTRY, tier2_n=5)
    with Session(engine) as session:
        committed_runs = session.execute(select(CensusRun)).scalars().all()
    engine.dispose()

    assert excinfo.value.page == 2
    assert excinfo.value.entries_seen == 1
    assert committed_runs == []


# --- salt persistence (final-review fix wave, Important #4/#5) -------------


def test_the_salt_used_for_coords_digest_is_persisted_on_the_run() -> None:
    """The bug `export_raw`'s own `_digest_for` docstring used to document:
    `run_census` generated a salt, used it for every record's
    `coords_digest`, then discarded it - nothing durable existed to publish
    or to verify the DB's digests against later. `run.salt` must now carry
    the exact bytes used, both in memory and once persisted."""
    items = [_server_item("pkg/bare-one")]
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, {})))
    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)
        assert run.salt is not None
        assert isinstance(run.salt, bytes)

        stored = session.execute(select(CensusRun).where(CensusRun.id == run.id)).scalar_one()
        assert stored.salt == run.salt
    engine.dispose()


def test_export_raw_digest_matches_the_records_own_coords_digest(tmp_path: Path) -> None:
    """The regression this whole fix exists for: `export_raw`, called with
    the run's own persisted salt (not a fresh one, as `cli.py`'s `census`
    command now does), must reproduce the exact digest already stored in
    `CensusRecord.coords_digest` for that record - proving the two are
    verifiable against each other, not just that both happen to be strings.
    """
    from agent_perimeter.report.census_report import export_raw

    items = [
        _server_item(
            "pkg/npm-one",
            packages=[{"registryType": "npm", "identifier": "npm-one", "version": "1.0.0"}],
        )
    ]
    downloads = {("npm", "npm-one"): 100}
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, downloads)))
    engine = _engine()
    with Session(engine) as session:
        # tier2_n=0: no artifact fetch, so feature_set_json stays {} - this
        # test is about the digest column, not about the two-stratum
        # classification export_raw also performs.
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=0)
        records = (
            session.execute(select(CensusRecord).where(CensusRecord.census_run_id == run.id))
            .scalars()
            .all()
        )
        assert run.salt is not None
        export_raw(run, records, salt=run.salt, out=tmp_path)

        body = (tmp_path / "records.csv").read_text(encoding="utf-8")
        record = records[0]
        assert record.coords_digest in body
    engine.dispose()


def test_fetch_failures_is_printed_even_when_zero() -> None:
    """B10: a number that only appears when it's bad is a number nobody trusts."""
    items = [_server_item("pkg/bare-one")]
    client = httpx.Client(transport=httpx.MockTransport(_handler({None: _page(items)}, {})))
    engine = _engine()
    with Session(engine) as session:
        run = run_census(session, client, endpoint=REGISTRY, tier2_n=5)
        assert run.fetch_failures == 0
        # The value is a real int either way, not an optional field a caller
        # has to special-case before printing it.
        assert isinstance(run.fetch_failures, int)
    engine.dispose()
