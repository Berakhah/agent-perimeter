# Task 6b report: `agent_perimeter/census/tier3.py`

## What was implemented

`agent_perimeter/census/tier3.py` — the Tier-3 remote-stratum probe. Public surface:

- `remote_only_stratum(entries)` — restates Task 2/`census.run._distribution`'s
  `remote_only` predicate (coords is None, no unmodeled package, `remotes` non-empty).
- `SampleFrame(seed, eligible, sample)` — a frozen dataclass; `sample_frame(entries, *, n=SAMPLE_SIZE, seed, already_contacted=frozenset())`
  draws a seeded random sample of `n` (default `SAMPLE_SIZE = 100`) from the stratum,
  after excluding any `registry_id` in `already_contacted`. Deterministic given the same
  entries, seed, and `already_contacted` set.
- `load_opt_out_hosts(path)` — one hostname per line, `#`-comments and blanks ignored,
  missing file → empty set.
- `probe_host(client, entry, *, user_agent=USER_AGENT, opt_out_hosts=frozenset())` — the
  per-host state machine: opt-out check → robots.txt fetch/check → exactly one
  `server/discover` POST. Returns a `HostResult(registry_id, target_url, status,
  skip_reason, fingerprint)`.
- `run_tier3(client, frame, *, user_agent=USER_AGENT, opt_out_hosts=frozenset())` — calls
  `probe_host` over every entry in `frame.sample`.
- `Tier3Fingerprint(features, protocol_versions_advertised, claim)` — observe-or-abstain
  feature set from the one discover response, `Claim` with `Derivation.PROBE`.
- `SkipReason` (`OPTED_OUT`, `ROBOTS_DISALLOWED`, `NO_REMOTE_URL`) and re-exported
  `USER_AGENT` (= `fetch.USER_AGENT`, not a new constant).

Also added `FetchStatus.UNREACHABLE` to `agent_perimeter/model/census.py` — see design
decisions below.

## Design decisions on the open points

**1. Persistence ("never contacted again, including on a re-run").** Chose the narrower
interface explicitly offered as acceptable in the spec: `sample_frame()` takes
`already_contacted: AbstractSet[str]` (registry ids) as a plain parameter and excludes
them from the eligible pool *before* drawing. `tier3.py` has no DB session, no import of
`agent_perimeter.db` or `sqlalchemy`. Reasoning: `run.py`'s integration is explicitly out
of scope for this task, and `run.py` importing `census.tier3` while `tier3.py` also
imported `run.py`'s DB session type would risk exactly the kind of coupling the census
package has been kept free of everywhere else (see `test_census_can_never_reach_a_transport_or_an_active_check`'s
whole rationale). A future integration task threads the actual lookup: query prior
`CensusRecord` rows for `fetch_status == FetchStatus.UNREACHABLE.value` and pass the
resulting `registry_id` set in. Proven end-to-end in
`test_a_host_marked_unreachable_is_never_drawn_into_a_resample`: run 1 samples every
host, one fails; run 2 (same entries/seed, `already_contacted` = run 1's unreachable set)
excludes that host from both `eligible` and `sample`, and a transport that raises if that
host's URL is ever dialled again proves no request happens.

**Added `FetchStatus.UNREACHABLE`** to `model/census.py` rather than inventing a parallel
vocabulary in `tier3.py`. The spec explicitly names this as the natural fit ("`unreachable`
— note existing values already exist... your call, but don't invent parallel meaning").
Since `tier3.py`'s `HostResult.status` is typed `FetchStatus | None` and will become
`CensusRecord.fetch_status` in a future integration, reusing the shared enum now (a
one-line, low-risk addition) avoids a translation layer later. Any skip that never sent a
request at all (opt-out, robots disallow, no remote URL) is `SkipReason`, not a
`FetchStatus` — it is not a "fetch outcome" because no fetch was attempted, and does not
mean "never contact again" (opt-out is re-checked from the maintained file every run;
robots.txt failures deserve a retry next run, not a permanent ban — see point 3 below).

**2. Opt-out list.** `load_opt_out_hosts(Path) -> frozenset[str]`, one hostname per line.
`probe_host`/`run_tier3` accept `opt_out_hosts: AbstractSet[str]` directly (not a path) so
the hot path never does file IO per host and stays trivially mockable. No example host or
path lives in `tier3.py`; both only appear in tests.

**3. Robots.txt failure semantics (not spelled out in the spec, my call).** A 200 is
parsed and obeyed; a 404 means no robots.txt, nothing to obey, proceed. Anything else
(connection error, timeout, non-200/404 status) **fails closed** — the host is skipped
this run (`SkipReason.ROBOTS_DISALLOWED`), not marked `UNREACHABLE`. This deliberately
does *not* use the more permissive convention some crawlers use (treat 4xx as "no
restrictions", 5xx as "try later") — given this project's fail-closed posture elsewhere
(scope files, hard rule 1), a robots.txt fetch that could not be read should not be
treated as silent permission. Because it is a `SkipReason`, not a `FetchStatus`, the host
is eligible again on the next run rather than banned forever over one transient 500.

**4. Rate limiting.** `TIER3_MIN_INTERVAL_S = 1.0` (slower than `fetch.py`'s registry
`0.5s` — a security-scanner-on-the-open-web context has no published rate limit to target,
so it errs slower), `time.sleep()` placed inside `_robots_allows`/`_discover` themselves,
right after the live HTTP call, so it fires exactly once per actual request made and never
fires for a skip that made no request (`test_rate_limit_is_not_applied_when_no_request_was_made`).

**5. Feature detection / observe-or-abstain.** `transport.revision.py` (and its
`PASSIVELY_OBSERVABLE_FEATURES`) cannot be imported here — `agent_perimeter.census` must
never reach `agent_perimeter.transport`, and `test_census_can_never_reach_a_transport_or_an_active_check`
applies to `tier3.py` too (no exclusion for it, unlike the two host/method tests). Wrote a
narrow, single-purpose reimplementation (`_observed_features`) that mirrors exactly
`revision._claimed_revision`'s discover-only branch: `Feature.SERVER_DISCOVER` (a result
came back at all) and `Feature.EXTENSIONS` (`capabilities.extensions` present) — nothing
else is ever inferred, because tier3 never calls `tools/list`, never opens a stream, and
never does a multi-step probe.
`test_result_type_is_never_inferred_from_a_discover_only_call` feeds a discover payload
that itself contains a `resultType` field (a real discover response can) and asserts
`Feature.RESULT_TYPE` is still absent — proving abstention, not just asserting a feature
list.

**6. User-Agent.** Reused `fetch.USER_AGENT` by import (`tier3.USER_AGENT is fetch.USER_AGENT`)
rather than mirroring it as a new constant, specifically because the "no host string"
structural test scans `tier3.py`'s raw source text for `https://...` — a duplicated
constant containing the contact URL literal would fail that test. The literal lives in
`fetch.py` (exempt from that particular test file's tier3 carve-out is irrelevant — the
scan only inspects `tier3.py`'s own source); importing the name introduces no new string
into `tier3.py`.

**7. JSON-RPC error responses.** A syntactically valid JSON-RPC error (`{"error": {...}}`,
no `result`) is treated as "no answer" → `UNREACHABLE`, same as a network failure or
malformed body. Simplest, most conservative reading of requirement 3 ("a non-answer is
recorded as unreachable") — a server that can't productively answer `server/discover`
gets no more attention than one that never answered at all.

**8. `Content-Type` header.** Deliberately *not* set manually
(`headers={"User-Agent": ...}` only, letting `httpx`'s `json=` kwarg set it). The literal
`"application/json"` fullmatches the AST test's `^[a-z]+/[a-zA-Z]+$` method-shape regex —
setting it by hand would have made `methods == {"server/discover", "application/json"}`
and failed `test_tier3_sends_exactly_one_method_and_owns_no_host`. Flagging this because
it is a genuinely easy trap: the constraint is about string *shape*, not about JSON-RPC
methods specifically.

## TDD evidence

RED: `tests/census/test_tier3.py` written first; `agent_perimeter/census/tier3.py` did not
exist, `uv run pytest tests/census/test_tier3.py` failed at collection
(`ImportError: cannot import name 'tier3'`). The pre-existing `test_tier3_sends_exactly_one_method_and_owns_no_host`
was also un-skipped before implementation existed (would fail on `TIER3.read_text` /
methods mismatch once collected — verified conceptually, collection error on the new file
blocked the whole session at that point so it wasn't separately re-run RED, but it could
not have passed against a nonexistent file either way).

GREEN: after implementing `tier3.py` (one interim fix: `collections.abc.AbstractSet`
doesn't exist — it's `collections.abc.Set`, imported as `Set as AbstractSet`; one interim
test-logic fix in `test_a_host_marked_unreachable_is_never_drawn_into_a_resample`, whose
mock handler order let the simulated connection error hit the robots.txt fetch first
instead of the discover call):

```
tests/census/test_tier3.py .............................. (31 passed)
tests/census/test_passive_only.py .... (4 passed, including the un-skipped structural test)
```

Full verification:
- `uv run ruff check .` — all checks passed (whole repo).
- `uv run mypy --strict agent_perimeter` — Success: no issues found in 89 source files.
- `uv run pytest tests/census/` — 94 passed.
- `uv run pytest -q` (full suite) — 578 passed, coverage 93.53% (floor 75%).

## Files changed

- `agent_perimeter/census/tier3.py` — new.
- `tests/census/test_tier3.py` — new, 31 tests.
- `agent_perimeter/model/census.py` — added `FetchStatus.UNREACHABLE`.
- `tests/census/test_passive_only.py` — removed the `@pytest.mark.skip` from
  `test_tier3_sends_exactly_one_method_and_owns_no_host`.

`git diff --stat` confirms scope is exactly these four files (two modified, two new); no
other file in the repo was touched.

## Self-review

- **Completeness:** all 11 numbered requirements addressed (single method / no fallback /
  no retry; n=100 seeded sample; unreachable persists via `already_contacted` and is
  proven never re-contacted in a two-run simulation; robots.txt honoured before any
  request, fail-closed; rate limit applied per live request only; contact URL in
  User-Agent via reuse; opt-out checked before both robots.txt and discover; `Derivation.PROBE`
  used, no new enum member added; observe-or-abstain reimplemented narrowly; seed +
  eligible population published on `SampleFrame`; every test runs against
  `httpx.MockTransport`, zero live requests). Both structural tests in
  `test_passive_only.py` pass, the previously-skipped one for real against the actual file.
- **Quality:** follows `fetch.py`'s `USER_AGENT`/rate-limit-constant conventions (reused
  the former outright, mirrored the latter's `ponytail:` comment style). `robotparser`
  (stdlib) used instead of hand-rolling a robots.txt parser — rung 3 of the ladder.
- **Discipline:** `grep -n "https\?://" agent_perimeter/census/tier3.py` — zero matches.
  No hardcoded hostname or path anywhere in the file; opt-out path, registry entries, and
  `already_contacted` set all arrive as parameters.
- **Testing:** `test_a_host_marked_unreachable_is_never_drawn_into_a_resample` runs two
  full sample→probe cycles and asserts the second cycle's transport handler is never
  invoked for the failed host's URL — not just that `sample_frame`/`probe_host` exist.
- **Security/ethics:** opt-out is checked first and unconditionally raises via
  `AssertionError` in the test transport if violated
  (`test_opted_out_host_gets_no_request_at_all_not_even_robots_txt` covers both the
  robots.txt fetch and the discover call). Robots.txt is checked before the discover POST
  in every code path, fail-closed on any fetch error.

## Concerns

- `run.py`/CLI integration (wiring `tier3.py` into `run_census()`, actually querying
  `CensusRecord` for the `already_contacted` set, and deciding how `SkipReason` outcomes
  get recorded, if at all) is intentionally untouched — flagging so it isn't assumed done.
- The choice to treat a JSON-RPC-level error response as `UNREACHABLE` (design decision 7)
  is defensible but is a real judgment call; a future task could split it into a distinct
  outcome (e.g. "answered, but declined") if that distinction turns out to matter for the
  published report.
- Robots.txt fail-closed-on-error (decision 3) trades population coverage for caution — a
  host with a flaky robots.txt endpoint may simply never get sampled successfully. This
  seemed like the right tradeoff for a scanner that has to publish its ethics story, but
  it is worth a second opinion before the first live run.
