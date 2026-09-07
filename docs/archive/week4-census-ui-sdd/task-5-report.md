# Task 5 report: Tier-2 sampling

## What was implemented

- `agent_perimeter/census/sample.py` — `RankSource`, `RankedEntry`, `SELECTION_METHOD`,
  `rank(client, entries) -> list[RankedEntry]`, `top_n(ranked, n) -> list[RankedEntry]`.
- `tests/census/test_sample.py` — the brief's 5 `top_n` tests verbatim, plus 5 new tests for `rank()`.
- `tests/census/factories.py` — `ranked(specs)` factory, since it did not exist yet.

`top_n()` is copied from the brief exactly (Step 2), unchanged.

## How `rank()` was designed

Interfaces was the only unresolved piece — the brief lists `rank(client, entries) -> list[RankedEntry]`
but shows no body. Modeled it directly on the house pattern already established in
`agent_perimeter/census/artifacts.py::_metadata` (sync `httpx.Client`, per-module `USER_AGENT` built
from `agent_perimeter.__version__`, a `match coords.ecosystem:` dispatch that mypy proves exhaustive
over the two current `Ecosystem` members):

- An entry with `coords is None` (a `remote_only` server, no package) short-circuits to
  `RankSource.UNAVAILABLE` before any HTTP call is made — verified by a test whose mock transport
  raises `AssertionError` if it is ever invoked.
- PyPI: GET `PYPI_DOWNLOADS.format(name=...)`, read `data.last_month` from the confirmed
  `{"data": {"last_month": N, ...}, ...}` shape. Any non-200 (429 included), a timeout/connection
  error, unparseable JSON, or a missing/non-int `last_month` all collapse to `downloads=None` →
  `RankSource.UNAVAILABLE`. No retry, no backoff — one attempt, one honest failure state.
- npm: GET `NPM_DOWNLOADS.format(name=...)`, read `downloads` from
  `{"downloads": N, "start": ..., "end": ..., "package": ...}`. The unknown-package shape
  (`{"error": "package ... not found"}`) has no `"downloads"` key at all — `doc.get("downloads")`
  returns `None`, same UNAVAILABLE path, no special-casing needed.
- A fixed `MIN_INTERVAL_S = 0.3` sleep after each PyPI call only (npm showed no throttling evidence
  in the ground truth) — marked with a `ponytail:` comment naming the ceiling (fixed delay, not a
  token bucket) and the upgrade path (swap for a token bucket if a published `Retry-After` ever
  demands more). This directly matches the task's own guidance not to build Task 2's
  `paginate`-grade retry/backoff machinery for a ranking pass that already treats a throttled entry
  as non-fatal.

`SELECTION_METHOD` gained a leading sentence: the registry API itself carries no
popularity/download/star/install-count field on any entry, which is why ranking goes out to
pypistats.org/api.npmjs.org in the first place. This is the correction from
`docs/superpowers/specs/2026-08-29-agent-perimeter-plan-revision.md` §Task 5 (confirmed by Task 2's
own registry fixtures — no such field appears in any row).

## TDD evidence

RED:
```
tests\census\test_sample.py:4: in <module>
    from agent_perimeter.census.sample import RankSource, rank, top_n
E   ModuleNotFoundError: No module named 'agent_perimeter.census.sample'
```

GREEN:
```
uv run pytest tests/census/test_sample.py -q
...
10 passed in 3.27s
```

## Descope lever (Step 3)

```
uv run python -c "
from agent_perimeter.census.sample import top_n
from tests.census.factories import ranked
pop = ranked([(f'p{i}', 1000 - i) for i in range(300)])
print(len(top_n(pop, 200)), len(top_n(pop, 50)))
"
```
Output: `200 50` — matches the brief's expected output exactly.

## Verification

- `uv run ruff check .` — All checks passed (whole repo).
- `uv run mypy --strict agent_perimeter` — Success: no issues found in 87 source files.
- `uv run pytest tests/census/` — 55 passed.
- `uv run pytest` (full repo, coverage on) — 537 passed, 93.16% total coverage (floor 75%).
  `sample.py` itself: 88% (uncovered lines are the `httpx.HTTPError`/`ValueError` exception
  branches in `_pypi_downloads`/`_npm_downloads` — same shape and same ratio as the untested
  exception branches already present in `fetch.py` (85%) and `artifacts.py` (83%), not a new gap
  this task introduced).

## Files changed

- `agent_perimeter/census/sample.py` (new)
- `tests/census/test_sample.py` (new)
- `tests/census/factories.py` (new)

Commit: `5ab877c` — "feat: deterministic within-ecosystem tier-2 sampling"

## Self-review

- **Completeness:** `top_n()` matches the brief byte-for-byte. `rank()` handles both real API
  success shapes and every ground-truth error case (429, non-200, timeout/connection error,
  malformed JSON, missing field/key). `SELECTION_METHOD` updated with the registry-has-no-popularity-
  field sentence.
- **Quality:** matches house style from `fetch.py`/`artifacts.py` — module docstring explaining the
  "why", per-module `USER_AGENT`, `match` dispatch over `Ecosystem` for mypy-proved exhaustiveness,
  `ponytail:` comment on the one deliberate corner cut (fixed delay vs. token bucket).
- **Discipline:** no retry/backoff — `_pypi_downloads`/`_npm_downloads` each make exactly one
  request and return `None` on any failure. This is deliberately thinner than Task 2's `paginate`
  because the task brief said so explicitly.
- **Testing:** `test_a_pypistats_429_is_unavailable_not_a_crash` and
  `test_an_npm_response_with_no_downloads_key_is_unavailable` both exercise the exact ground-truth
  failure shapes given in the task instructions, via `httpx.MockTransport` — no live network call
  anywhere in the test file.

## Concerns

None blocking. One judgment call worth flagging: `rank()`'s signature is `rank(client, entries)`
exactly as specified, with no extra keyword parameters (e.g. no injectable delay override for
tests) — I kept `MIN_INTERVAL_S` as a plain module constant rather than adding a test-seam
parameter, since the existing `fetch.py::paginate` precedent also hardcodes its inter-page delay
and tolerates the resulting ~0.5s per affected test. My PyPI-path tests each incur one 0.3s sleep;
total test-suite cost is small (census suite runs in ~3s) and not worth a speculative parameter
for a future need that hasn't shown up yet.
