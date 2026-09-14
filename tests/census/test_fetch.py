import httpx
import pytest

from agent_perimeter.census import fetch
from agent_perimeter.census.fetch import USER_AGENT, FetchLog, PaginationTruncated, paginate
from agent_perimeter.model.census import FetchStatus

ENDPOINT = "https://example.invalid/v0/servers"


def _transport(pages: list[dict]) -> httpx.MockTransport:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        i = calls["n"]
        calls["n"] += 1
        return httpx.Response(200, json=pages[min(i, len(pages) - 1)])

    return httpx.MockTransport(handler)


def _full_page(page_no: int, next_cursor: str | None, n: int = fetch.PAGE_LIMIT) -> dict:
    return {
        "servers": [
            {"server": {"name": f"srv.example/p{page_no}-n{i}", "version": "1.0.0"}}
            for i in range(n)
        ],
        "metadata": {"count": n, **({"nextCursor": next_cursor} if next_cursor else {})},
    }


def _sequenced_transport(responses: list[httpx.Response]) -> httpx.MockTransport:
    """Reply with each response in order; the last one repeats forever."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        i = calls["n"]
        calls["n"] += 1
        return responses[min(i, len(responses) - 1)]

    return httpx.MockTransport(handler)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetch.time, "sleep", lambda _s: None)


def test_a_page_failure_after_retries_raises_instead_of_truncating(no_sleep: None) -> None:
    """A transient failure on page 3 used to make paginate() return silently and the
    run recorded the 200-entry prefix as population_size. A prefix is not a census."""
    responses = [
        httpx.Response(200, json=_full_page(1, "c1")),
        httpx.Response(200, json=_full_page(2, "c2")),
        httpx.Response(500),
    ]
    log = FetchLog()
    client = httpx.Client(transport=_sequenced_transport(responses))
    with pytest.raises(PaginationTruncated) as excinfo:
        list(paginate(client, ENDPOINT, log, max_retries=3))
    assert excinfo.value.page == 3
    assert excinfo.value.entries_seen == 200
    assert "page 3" in excinfo.value.detail
    assert log.failures == 1


def test_a_transient_5xx_is_retried_and_the_population_is_complete(no_sleep: None) -> None:
    responses = [
        httpx.Response(200, json=_full_page(1, "c1")),
        httpx.Response(200, json=_full_page(2, "c2")),
        httpx.Response(503),
        httpx.Response(200, json=_full_page(3, None, n=20)),
    ]
    log = FetchLog()
    client = httpx.Client(transport=_sequenced_transport(responses))
    entries = list(paginate(client, ENDPOINT, log, max_retries=3))
    assert len(entries) == 220
    assert log.failures == 0
    assert log.population_is_complete is True


def test_a_5xx_retry_backs_off_between_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(fetch.time, "sleep", sleeps.append)
    log = FetchLog()
    client = httpx.Client(transport=_sequenced_transport([httpx.Response(502)]))
    with pytest.raises(PaginationTruncated):
        list(paginate(client, ENDPOINT, log, max_retries=3))
    assert sleeps == [fetch.MIN_INTERVAL_S * 1, fetch.MIN_INTERVAL_S * 2]


def test_full_first_page_without_cursor_raises(no_sleep: None) -> None:
    log = FetchLog()
    client = httpx.Client(transport=_transport([_full_page(1, None)]))
    with pytest.raises(PaginationTruncated) as excinfo:
        list(paginate(client, ENDPOINT, log))
    assert excinfo.value.page == 1
    assert excinfo.value.entries_seen == fetch.PAGE_LIMIT
    assert log.population_is_complete is False


def test_a_4xx_other_than_429_fails_immediately_without_retry(no_sleep: None) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    log = FetchLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(PaginationTruncated) as excinfo:
        list(paginate(client, ENDPOINT, log, max_retries=3))
    assert calls["n"] == 1
    assert "status 404" in excinfo.value.detail


def test_paginate_follows_the_cursor_to_exhaustion(registry_pages: list[dict]) -> None:
    client = httpx.Client(transport=_transport(registry_pages))
    entries = list(paginate(client, "https://example.invalid/v0/servers", FetchLog()))
    assert len(entries) == 3
    assert entries[0].registry_id


def test_user_agent_identifies_the_tool_and_a_contact_url() -> None:
    assert "agent-perimeter" in USER_AGENT
    assert "https://" in USER_AGENT


def test_a_throttled_page_is_recorded_not_swallowed(no_sleep: None) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    log = FetchLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(PaginationTruncated) as excinfo:
        list(paginate(client, ENDPOINT, log, max_retries=1))
    assert log.failures == 1
    assert log.outcomes[0].status is FetchStatus.THROTTLED
    assert excinfo.value.detail == log.outcomes[0].detail


def test_a_partial_population_is_never_reported_as_complete() -> None:
    log = FetchLog()
    log.record(FetchStatus.THROTTLED, "page 4")
    assert log.population_is_complete is False


def test_a_full_first_page_with_no_cursor_is_flagged_not_completed(no_sleep: None) -> None:
    """A page1 returning exactly `limit` rows with no cursor is far more likely a
    broken cursor read (the exact bug this module was built to stop repeating -
    see docs/methodology.md ## Census collection) than a registry that happens to
    hold precisely 100 entries. The census must not silently call that complete.
    """
    page = {
        "servers": [
            {"server": {"name": f"srv.example/n{i}", "version": "1.0.0"}} for i in range(100)
        ],
        "metadata": {"count": 100},
    }
    log = FetchLog()
    client = httpx.Client(transport=_transport([page]))
    with pytest.raises(PaginationTruncated):
        list(paginate(client, ENDPOINT, log))
    assert log.population_is_complete is False
    assert log.outcomes[0].status is FetchStatus.PARSE_ERROR


def test_every_retry_timing_out_logs_exactly_one_failure_not_one_per_attempt(
    no_sleep: None,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("boom", request=request)

    log = FetchLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(PaginationTruncated) as excinfo:
        list(paginate(client, ENDPOINT, log, max_retries=3))
    assert excinfo.value.entries_seen == 0
    assert log.failures == 1
    assert log.outcomes[0].status is FetchStatus.TIMEOUT


def test_an_unmodeled_registry_type_is_distinguishable_from_no_package_at_all() -> None:
    oci_page = {
        "servers": [
            {
                "server": {
                    "name": "example/oci-server",
                    "version": "1.0.0",
                    "packages": [
                        {
                            "registryType": "oci",
                            "identifier": "example/oci-server",
                            "version": "1.0.0",
                        }
                    ],
                }
            }
        ],
        "metadata": {"count": 1},
    }
    bare_page = {
        "servers": [{"server": {"name": "example/bare-server", "version": "1.0.0"}}],
        "metadata": {"count": 1},
    }

    oci_entries = list(
        paginate(
            httpx.Client(transport=_transport([oci_page])),
            "https://example.invalid/v0/servers",
            FetchLog(),
        )
    )
    bare_entries = list(
        paginate(
            httpx.Client(transport=_transport([bare_page])),
            "https://example.invalid/v0/servers",
            FetchLog(),
        )
    )

    assert oci_entries[0].coords is None
    assert oci_entries[0].has_unmodeled_package is True
    assert bare_entries[0].coords is None
    assert bare_entries[0].has_unmodeled_package is False


def test_paginate_requests_version_latest_on_every_page(registry_pages: list[dict]) -> None:
    seen_params: list[httpx.QueryParams] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.append(request.url.params)
        i = len(seen_params) - 1
        return httpx.Response(200, json=registry_pages[min(i, len(registry_pages) - 1)])

    client = httpx.Client(transport=httpx.MockTransport(handler))
    list(paginate(client, "https://example.invalid/v0/servers", FetchLog()))
    assert seen_params, "expected at least one request"
    assert all(params.get("version") == "latest" for params in seen_params)
