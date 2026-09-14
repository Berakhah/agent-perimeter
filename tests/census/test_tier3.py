"""Tier-3 census: sampling, robots.txt, opt-out, rate-limit, and probe outcomes.

Every test here runs against a mocked httpx transport - see the module
docstring on tier3.py and requirement 11 of the task spec: no live Tier-3
request is ever made as part of this test suite.
"""

from __future__ import annotations

import httpx
import pytest

from agent_perimeter._contracts import Derivation, Method
from agent_perimeter.census import tier3
from agent_perimeter.census.fetch import USER_AGENT, RegistryEntry
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords
from agent_perimeter.model.feature import Feature


def _entry(
    registry_id: str,
    *,
    remotes: tuple[str, ...] = (),
    coords: PackageCoords | None = None,
    has_unmodeled_package: bool = False,
) -> RegistryEntry:
    return RegistryEntry(
        registry_id=registry_id,
        name=registry_id,
        coords=coords,
        repository_url=None,
        remotes=remotes,
        has_unmodeled_package=has_unmodeled_package,
    )


REMOTE_ONLY = [
    _entry("srv/a", remotes=("https://a.example.invalid/mcp",)),
    _entry("srv/b", remotes=("https://b.example.invalid/mcp",)),
    _entry("srv/c", remotes=("https://c.example.invalid/mcp",)),
    _entry("srv/d", remotes=("https://d.example.invalid/mcp",)),
    _entry("srv/e", remotes=("https://e.example.invalid/mcp",)),
]

DISCOVER_RESULT = {
    "resultType": "complete",
    "protocolVersions": ["2026-07-28"],
    "capabilities": {"tools": {}, "extensions": {}},
}


def _jsonrpc_ok(result: dict[str, object] = DISCOVER_RESULT) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})


def _robots_allow_all() -> httpx.Response:
    return httpx.Response(200, text="User-agent: *\nAllow: /\n")


def _robots_disallow_all() -> httpx.Response:
    return httpx.Response(200, text="User-agent: *\nDisallow: /\n")


def _no_robots_txt() -> httpx.Response:
    return httpx.Response(404)


def _handler_for(
    robots: dict[str, httpx.Response] | None = None,
    discover: dict[str, httpx.Response] | None = None,
) -> httpx.MockTransport:
    robots = robots or {}
    discover = discover or {}

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if request.url.path == "/robots.txt":
            if host in robots:
                return robots[host]
            return httpx.Response(404)
        if host in discover:
            return discover[host]
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    return httpx.MockTransport(handler)


# --- User-Agent / reuse -----------------------------------------------------


def test_tier3_reuses_fetchs_user_agent_rather_than_duplicating_one() -> None:
    assert tier3.USER_AGENT is USER_AGENT
    assert "agent-perimeter" in tier3.USER_AGENT


# --- stratum classification --------------------------------------------------


def test_remote_only_stratum_excludes_entries_with_a_package_or_unmodeled_package() -> None:
    entries = [
        _entry(
            "has-coords",
            remotes=("https://x.example.invalid/mcp",),
            coords=PackageCoords(ecosystem=Ecosystem.PYPI, name="x"),
        ),
        _entry(
            "has-unmodeled", remotes=("https://y.example.invalid/mcp",), has_unmodeled_package=True
        ),
        _entry("no-remotes"),
        _entry("remote-only", remotes=("https://z.example.invalid/mcp",)),
    ]
    stratum = tier3.remote_only_stratum(entries)
    assert [e.registry_id for e in stratum] == ["remote-only"]


# --- sampling determinism ----------------------------------------------------


def test_sample_frame_is_deterministic_given_the_same_population_and_seed() -> None:
    frame1 = tier3.sample_frame(REMOTE_ONLY, n=3, seed=7)
    frame2 = tier3.sample_frame(REMOTE_ONLY, n=3, seed=7)
    assert [e.registry_id for e in frame1.sample] == [e.registry_id for e in frame2.sample]


def test_sample_frame_a_different_seed_can_pick_a_different_sample() -> None:
    frame1 = tier3.sample_frame(REMOTE_ONLY, n=3, seed=1)
    frame2 = tier3.sample_frame(REMOTE_ONLY, n=3, seed=2)
    assert [e.registry_id for e in frame1.sample] != [e.registry_id for e in frame2.sample]


def test_sample_frame_n_larger_than_the_population_returns_the_population() -> None:
    frame = tier3.sample_frame(REMOTE_ONLY, n=200, seed=1)
    assert len(frame.sample) == len(REMOTE_ONLY)


def test_sample_frame_publishes_the_seed_and_the_eligible_population() -> None:
    frame = tier3.sample_frame(REMOTE_ONLY, n=3, seed=42)
    assert frame.seed == 42
    assert {e.registry_id for e in frame.eligible} == {e.registry_id for e in REMOTE_ONLY}
    assert set(e.registry_id for e in frame.sample) <= set(e.registry_id for e in frame.eligible)


def test_sample_frame_excludes_already_contacted_hosts_from_eligible_and_sample() -> None:
    frame = tier3.sample_frame(REMOTE_ONLY, n=200, seed=1, already_contacted={"srv/c"})
    assert "srv/c" not in {e.registry_id for e in frame.eligible}
    assert "srv/c" not in {e.registry_id for e in frame.sample}
    assert len(frame.sample) == len(REMOTE_ONLY) - 1


# --- the unreachable-never-recontacted guarantee, proven end to end --------


def test_a_host_marked_unreachable_is_never_drawn_into_a_resample() -> None:
    """Simulates two separate `agent-perimeter census` invocations.

    Run 1 samples every remote-only host and one of them (srv/c) fails to
    answer. Run 2, given that outcome fed back in as `already_contacted`,
    must neither draw srv/c into its sample nor issue it any request -
    proven here by a transport that raises if srv/c's host is ever dialled.
    """
    fails_host = "c.example.invalid"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        if request.url.host == fails_host:
            raise httpx.ConnectError("connection refused", request=request)
        return _jsonrpc_ok()

    frame1 = tier3.sample_frame(REMOTE_ONLY, n=len(REMOTE_ONLY), seed=1)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    results1 = tier3.run_tier3(client, frame1)
    unreachable = {r.registry_id for r in results1 if r.status is FetchStatus.UNREACHABLE}
    assert unreachable == {"srv/c"}

    frame2 = tier3.sample_frame(
        REMOTE_ONLY, n=len(REMOTE_ONLY), seed=1, already_contacted=unreachable
    )
    assert "srv/c" not in {e.registry_id for e in frame2.sample}

    def handler_forbids_c(request: httpx.Request) -> httpx.Response:
        if request.url.host == fails_host:
            raise AssertionError("srv/c must never be contacted again")
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        return _jsonrpc_ok()

    client2 = httpx.Client(transport=httpx.MockTransport(handler_forbids_c))
    results2 = tier3.run_tier3(client2, frame2)
    assert "srv/c" not in {r.registry_id for r in results2}


# --- robots.txt ---------------------------------------------------------


def test_robots_disallow_blocks_the_probe_before_any_discover_call() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(robots={"a.example.invalid": _robots_disallow_all()})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.status is None
    assert result.skip_reason is tier3.SkipReason.ROBOTS_DISALLOWED
    assert result.fingerprint is None


def test_robots_allow_lets_the_probe_through() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(
        robots={"a.example.invalid": _robots_allow_all()},
        discover={"a.example.invalid": _jsonrpc_ok()},
    )
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.OK


def test_missing_robots_txt_is_treated_as_no_restrictions() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(discover={"a.example.invalid": _jsonrpc_ok()})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.OK


def test_a_robots_txt_fetch_that_errors_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(500)
        raise AssertionError("discover must not be reached when robots.txt could not be read")

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.status is None
    assert result.skip_reason is tier3.SkipReason.ROBOTS_DISALLOWED


# --- opt-out list --------------------------------------------------------


def test_opted_out_host_gets_no_request_at_all_not_even_robots_txt() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"opted-out host must never be contacted: {request.url}")

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry, opt_out_hosts=frozenset({"a.example.invalid"}))
    assert result.status is None
    assert result.skip_reason is tier3.SkipReason.OPTED_OUT
    assert result.fingerprint is None


def test_load_opt_out_hosts_reads_one_hostname_per_line(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "opt-out.txt"
    path.write_text("a.example.invalid\n# a comment\n\nB.example.invalid\n", encoding="utf-8")
    hosts = tier3.load_opt_out_hosts(path)
    assert hosts == frozenset({"a.example.invalid", "b.example.invalid"})


def test_load_opt_out_hosts_missing_file_is_an_empty_set(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert tier3.load_opt_out_hosts(tmp_path / "does-not-exist.txt") == frozenset()


# --- rate limiting ---------------------------------------------------------


def test_rate_limit_is_applied_after_each_live_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[float] = []
    monkeypatch.setattr(tier3.time, "sleep", lambda s: calls.append(s))

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(
        robots={"a.example.invalid": _robots_allow_all()},
        discover={"a.example.invalid": _jsonrpc_ok()},
    )
    client = httpx.Client(transport=handler)
    tier3.probe_host(client, entry)
    assert calls == [tier3.TIER3_MIN_INTERVAL_S, tier3.TIER3_MIN_INTERVAL_S]


def test_rate_limit_is_not_applied_when_no_request_was_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[float] = []
    monkeypatch.setattr(tier3.time, "sleep", lambda s: calls.append(s))

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: (_ for _ in ()).throw(AssertionError("no request expected"))
        )
    )
    tier3.probe_host(client, entry, opt_out_hosts=frozenset({"a.example.invalid"}))
    assert calls == []


# --- probe outcomes: unreachable ------------------------------------------


def test_connection_error_is_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        raise httpx.ConnectError("refused", request=request)

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.UNREACHABLE
    assert result.fingerprint is None


def test_non_200_is_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        return httpx.Response(503)

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.UNREACHABLE


def test_malformed_json_body_is_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        return httpx.Response(200, text="not json")

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.UNREACHABLE


def test_a_jsonrpc_error_response_is_unreachable_not_a_partial_answer() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "not found"}}
        )

    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.status is FetchStatus.UNREACHABLE


def test_entry_with_no_remote_url_is_skipped_without_any_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected for an entry with no remote url")

    entry = _entry("srv/a", remotes=())
    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = tier3.probe_host(client, entry)
    assert result.skip_reason is tier3.SkipReason.NO_REMOTE_URL
    assert result.status is None


# --- feature detection: observe or abstain --------------------------------


def test_a_successful_probe_observes_server_discover_and_extensions() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(discover={"a.example.invalid": _jsonrpc_ok()})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.fingerprint is not None
    assert result.fingerprint.features == frozenset({Feature.SERVER_DISCOVER, Feature.EXTENSIONS})


def test_result_type_is_never_inferred_from_a_discover_only_call() -> None:
    """The discover payload itself carries a `resultType` field (a real MCP
    server's server/discover result can), but RESULT_TYPE is only ever
    observed from tools/list (see transport.revision._observed_features) -
    and tier3 never calls tools/list. Observe or abstain: it must not be
    granted just because the string happens to be present here.
    """
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    discover_without_extensions = {"resultType": "complete", "protocolVersions": ["2026-07-28"]}
    handler = _handler_for(discover={"a.example.invalid": _jsonrpc_ok(discover_without_extensions)})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.fingerprint is not None
    assert Feature.RESULT_TYPE not in result.fingerprint.features
    assert Feature.EXTENSIONS not in result.fingerprint.features
    assert result.fingerprint.features == frozenset({Feature.SERVER_DISCOVER})


def test_fingerprint_claim_uses_probe_derivation() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(discover={"a.example.invalid": _jsonrpc_ok()})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.fingerprint is not None
    assert result.fingerprint.claim.method is Method.DETERMINISTIC
    assert result.fingerprint.claim.derivation is Derivation.PROBE


def test_protocol_versions_advertised_are_captured() -> None:
    entry = _entry("srv/a", remotes=("https://a.example.invalid/mcp",))
    handler = _handler_for(discover={"a.example.invalid": _jsonrpc_ok()})
    client = httpx.Client(transport=handler)
    result = tier3.probe_host(client, entry)
    assert result.fingerprint is not None
    assert result.fingerprint.protocol_versions_advertised == ("2026-07-28",)


# --- run_tier3 orchestrates probe_host over a whole sample ------------------


def test_run_tier3_probes_every_host_in_the_sample() -> None:
    frame = tier3.sample_frame(REMOTE_ONLY, n=len(REMOTE_ONLY), seed=3)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return _no_robots_txt()
        return _jsonrpc_ok()

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = tier3.run_tier3(client, frame)
    assert {r.registry_id for r in results} == {e.registry_id for e in REMOTE_ONLY}
    assert all(r.status is FetchStatus.OK for r in results)
