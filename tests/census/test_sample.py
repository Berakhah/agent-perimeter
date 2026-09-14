import httpx
import pytest

from agent_perimeter.census import sample
from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.census.sample import RankSource, rank, top_n
from agent_perimeter.model.census import Ecosystem, PackageCoords
from tests.census.factories import ranked


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """rank() paces pypistats at MIN_INTERVAL_S and backs off seconds on 429;
    neither wait belongs in a unit test. Tests that measure the backoff
    re-patch sleep with a recorder."""
    monkeypatch.setattr(sample.time, "sleep", lambda _s: None)


def test_selection_is_deterministic() -> None:
    pop = ranked([("a", 10), ("b", 30), ("c", 30), ("d", 5)])
    assert [e.entry.name for e in top_n(pop, 2)] == [e.entry.name for e in top_n(pop, 2)]


def test_ties_break_on_registry_id_not_arrival_order() -> None:
    pop = ranked([("zeta", 30), ("alpha", 30)])
    assert [e.entry.name for e in top_n(pop, 2)] == ["alpha", "zeta"]


def test_ranking_happens_within_an_ecosystem_never_across() -> None:
    """PyPI and npm counts are different measurements. Merging them is a lie."""
    pop = ranked([("py-a", 100, "pypi"), ("js-a", 5, "npm")])
    selected = top_n(pop, 2)
    assert {e.rank_source for e in selected} == {
        RankSource.PYPI_RECENT_DOWNLOADS,
        RankSource.NPM_LAST_MONTH_DOWNLOADS,
    }


def test_an_entry_with_no_download_metric_is_excluded_and_counted() -> None:
    pop = ranked([("a", 10), ("b", None)])
    selected = top_n(pop, 5)
    assert len(selected) == 1
    assert sum(1 for e in pop if e.rank_source is RankSource.UNAVAILABLE) == 1


def test_n_larger_than_the_population_returns_the_population() -> None:
    assert len(top_n(ranked([("a", 1)]), 200)) == 1


def _entry(name: str, ecosystem: Ecosystem | None) -> RegistryEntry:
    coords = PackageCoords(ecosystem=ecosystem, name=name) if ecosystem is not None else None
    return RegistryEntry(registry_id=name, name=name, coords=coords, repository_url=None)


def test_rank_reads_pypi_recent_downloads_from_pypistats() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "pypistats.org" in str(request.url)
        return httpx.Response(200, json={"data": {"last_month": 4200}, "package": "astro"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = rank(client, [_entry("astro", Ecosystem.PYPI)])
    assert result[0].downloads == 4200
    assert result[0].rank_source is RankSource.PYPI_RECENT_DOWNLOADS


def test_rank_reads_npm_last_month_downloads_from_api_npmjs() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "api.npmjs.org" in str(request.url)
        return httpx.Response(200, json={"downloads": 900, "package": "left-pad"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = rank(client, [_entry("left-pad", Ecosystem.NPM)])
    assert result[0].downloads == 900
    assert result[0].rank_source is RankSource.NPM_LAST_MONTH_DOWNLOADS


def test_a_pypistats_429_is_unavailable_not_a_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = rank(client, [_entry("astro", Ecosystem.PYPI)])
    assert result[0].downloads is None
    assert result[0].rank_source is RankSource.UNAVAILABLE


def _sequenced_client(responses: list[httpx.Response]) -> httpx.Client:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        i = calls["n"]
        calls["n"] += 1
        return responses[min(i, len(responses) - 1)]

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_pypi_429_is_retried_with_backoff_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """pypistats.org 429'd 3 of 6 probes on 2026-09-14 with no retry, so most PyPI
    entries ranked UNAVAILABLE and could never enter tier 2. A throttle is a wait,
    not a verdict."""
    sleeps: list[float] = []
    monkeypatch.setattr(sample.time, "sleep", sleeps.append)
    client = _sequenced_client(
        [
            httpx.Response(429),
            httpx.Response(429),
            httpx.Response(200, json={"data": {"last_month": 123}, "package": "pkg"}),
        ]
    )
    assert sample._pypi_downloads(client, "pkg") == 123
    assert sleeps == list(sample.PYPI_429_BACKOFF_S[:2])


def test_pypi_429_on_every_attempt_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(sample.time, "sleep", sleeps.append)
    client = _sequenced_client([httpx.Response(429)] * (1 + len(sample.PYPI_429_BACKOFF_S)))
    assert sample._pypi_downloads(client, "pkg") is None
    # Every backoff step was used and no sleep follows the final refusal.
    assert sleeps == list(sample.PYPI_429_BACKOFF_S)


def test_pypi_interval_and_backoff_are_the_2026_09_14_values() -> None:
    assert sample.MIN_INTERVAL_S == 1.0
    assert sample.PYPI_429_BACKOFF_S == (2.0, 5.0, 10.0)


def test_an_npm_response_with_no_downloads_key_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": "package left-pad-nope not found"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = rank(client, [_entry("left-pad-nope", Ecosystem.NPM)])
    assert result[0].downloads is None
    assert result[0].rank_source is RankSource.UNAVAILABLE


def test_an_entry_with_no_coords_is_unavailable_without_a_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("rank() must not make a network call for an entry with no coords")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = rank(client, [_entry("remote-only-server", None)])
    assert result[0].downloads is None
    assert result[0].rank_source is RankSource.UNAVAILABLE
