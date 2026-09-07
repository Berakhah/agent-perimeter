# Final review fix wave — report

Base commit: `e4d9564`. All six items from `final-review-fix-brief.md` are fixed in one pass on
`week4-census-ui`, in the same worktree, no new worktree created.

## 1. [Critical] No CORS on the FastAPI app

`agent_perimeter/api/app.py::create_app()` now adds `CORSMiddleware` right after `app = FastAPI(...)`
and before the routers are included:

- `allow_origins` comes from `AP_CORS_ORIGINS` (comma-separated), defaulting to
  `http://localhost:3000`; split-and-stripped so a blank/whitespace value never becomes `[""]`
  (Starlette treats `""` as a wildcard-adjacent match-everything origin, which would be worse than
  no CORS at all).
- `allow_methods=["*"]`, `allow_headers=["*"]`, `allow_credentials=False` (this API has no
  cookies/auth — the auth/SSRF gap is the explicitly excluded, human-confirmed decision, not this
  middleware's job).
- `.env.example` gets `AP_CORS_ORIGINS=http://localhost:3000` with a one-line comment.
- `docker-compose.yml`'s `api` service environment gets
  `AP_CORS_ORIGINS: ${AP_CORS_ORIGINS:-http://localhost:3000}`, mirroring `AP_CONTACT_URL`'s
  existing pass-through style, so a bare `docker compose up` still works with no `.env` edits.

New test file `tests/api/test_cors.py` (follows `tests/api/test_health.py`'s layout/style):
allowed-origin request gets the header back with the right value, an unrelated origin gets no
header, a preflight `OPTIONS` for the allowed origin succeeds, and a blank/whitespace
`AP_CORS_ORIGINS` produces zero allowed origins (not a wildcard). 6 tests, all passing.

## 2. [Important] Screen 2 falsely claimed "No findings" unconditionally

`web/app/scans/[id]/page.tsx`: the terminal-frame handler now calls `getScan(id)` (real path only —
`if (!fixture)`) the instant the terminal event arrives, and stores `findings_count` in a new
`findingsCount` state (reset to `undefined` at the top of the effect, same as the other per-run
state). The terminal-summary ternary now branches:

- `fixture` (any of the three canned scenarios) → unchanged `EmptyState` copy. None of
  `streaming`/`degraded`/`deterministic` represents an unclean run, so fixture mode needed no
  change — verified by grepping `tests/` for every place that asserts on this screen's terminal
  copy before touching anything (`live-scan.spec.ts`, `a11y.spec.ts`).
- `findingsCount === 0` (real path) → same unchanged `EmptyState` copy — this is the one case
  where "No findings" is actually true.
- `findingsCount` is a positive number → a new `data-testid="findings-summary"` paragraph stating
  `"{n} finding(s) — see the findings link above."`, reusing the existing `findings-link` anchor at
  the top of the page rather than inventing a second link.
- `findingsCount` is `undefined` (fetch not yet resolved, fetch failed, or the field is genuinely
  absent) → `"findings count unknown — see the findings link above to check."`, matching
  `ConformanceStrip`'s `revisionClaimed` "absence reads as unknown, not a negative claim" tone and
  precedent exactly.

Updated the file's own docstring to describe the fix and to correct two sentences that were about
to go stale (the "no live backend reachable ... isn't exercised by any test here" claim, since the
new test below is now the first to exercise the real branch).

New tests in `web/tests/live-scan.spec.ts` (this file had zero non-fixture-path coverage before —
confirmed directly in the page's own docstring): two tests use `page.route()` to mock
`**/api/scans/1/events` (one SSE terminal frame) and `**/api/scans/1` (real `getScan` response),
then navigate to `/scans/1` with no `?fixture=` param —

- non-zero `findings_count` → `findings-summary` shows "3 findings", "No findings..." text is
  absent.
- `findings_count` omitted from the response → `findings-summary` shows "unknown", "No findings..."
  text is absent.

## 3. [Important] `/findings` fixture-demo route shipped as a real production page

- `web/tests/tokens.spec.ts`: both `page.goto("/findings?fixture=mixed")` calls now target
  `/scans/1/findings?fixture=mixed`.
- `web/tests/provenance-rail.spec.ts`: the one `goto` retargeted the same way. The real route's
  `mixed` fixture carries several claim-activatable rows (the old fixture-demo page rendered
  exactly one standalone `Claim` via `ProvenanceDemo`, unrelated to `FindingsTable`), so
  `getByTestId("claim")` needed `.first()` to avoid a Playwright strict-mode violation — added,
  with a comment, matching `findings.spec.ts`'s own existing `.first()` precedent on this same
  testid/route.
- Deleted `web/app/findings/page.tsx` and `web/app/findings/ProvenanceDemo.tsx` (`git rm`). Grepped
  the whole `web/` tree first for any other importer of `ProvenanceDemo` or the `/findings` route —
  none found. The now-empty `web/app/findings/` directory disappeared with the last file.

Verified: `tests/tokens.spec.ts`, `tests/provenance-rail.spec.ts`, `tests/findings.spec.ts`,
`tests/a11y.spec.ts` (37 tests) all pass together, and the full 64-test suite passes (see below).

## 4 & 5. `census --out` never rendered the report; the salt was generated then discarded

**Schema.** `agent_perimeter/db/models.py::CensusRun` gets one new column:
`salt: Mapped[bytes | None] = mapped_column(nullable=True)` — nullable per the brief (pre-release
data, no backfill obligation), not because a salt is ever optional going forward.

**Migration.** `migrations/versions/0004_census_run_salt.py`, `down_revision = '0003'`,
`revision = '0004'`, same import/header style as `0003_census.py`: `op.add_column('census_run',
sa.Column('salt', sa.LargeBinary(), nullable=True))` / matching `drop_column` on downgrade.

**`agent_perimeter/census/run.py::run_census`.** After generating `salt = secrets.token_bytes(32)`
(same line as before), added `run.salt = salt` so it's persisted on the row `run_census` already
created and flushed. Deleted the `ponytail:` comment describing the gap (now closed) and replaced
it with a factual note pointing at where the salt is persisted and why (`export_raw`'s
`_digest_for` docstring). That docstring (`agent_perimeter/report/census_report.py::_digest_for`)
was also updated — it used to state plainly that the DB's salt "cannot be reproduced later"; it now
says the exported digest matches the DB row's own `coords_digest` by construction when the caller
passes `run.salt`, which `cli.py`'s `census` command now does.

**`agent_perimeter/cli.py::census()`.** Inside the still-open session, after the four existing
summary `typer.echo` lines: queries `CensusRecord` rows for `run.id` via `select(...).where(...)`
(matching the query pattern already used throughout `census/run.py` and its tests), calls
`render_census(run, records)` and writes it to `out / "census.html"`, then calls `export_raw(run,
records, salt=run.salt, out=out)` — passing the now-persisted salt rather than generating a fresh
one — and echoes both written paths in the same `typer.echo` style as the rest of the function.
`run.salt` is `bytes | None` on the model; since `run_census` always sets it and the project's ruff
config forbids `assert` in production code (`S101`, ignored only under `tests/**`), a plain
`if run.salt is None: raise RuntimeError(...)` narrows the type for mypy instead of an assert.

**Tests.**
- `tests/census/test_run.py`: two new tests. One asserts `run.salt is not None` right after
  `run_census` and that the persisted row's `salt` column matches it exactly (`stored.salt ==
  run.salt`). The other is the actual regression test for the bug: runs the real `run_census`
  against a mocked registry, then calls `export_raw(run, records, salt=run.salt, out=tmp_path)` and
  asserts the record's own `coords_digest` (computed inside `run_census` with that same salt)
  literally appears in the exported `records.csv` — proving the two are reproducible against each
  other, not just that both are non-empty strings.
- `tests/test_cli.py`: added `test_census_out_writes_the_html_report_and_raw_export`, asserting
  `agent-perimeter census --out <tmpdir>` (with `run_census` mocked, `--database-url` pointed at a
  throwaway sqlite file, matching this file's existing hermetic-CLI-test convention) produces both
  `census.html` and `records.csv` in that directory, and that both `typer.echo` lines name the
  right paths.
- `_stub_census_run()` (used by the two pre-existing census CLI tests) had to grow from 4 fields
  to a full field set (`id`, `started_at`, `finished_at`, `tool_version`, `registry_endpoint`,
  `salt`) — the new CLI code path reads all of them via `render_census`/`export_raw`/the
  `CensusRecord` query, so the two pre-existing tests
  (`test_census_defaults_to_the_project_postgres_not_sqlite`,
  `test_census_database_url_can_be_overridden_without_a_live_postgres`) would otherwise crash on a
  bare 4-field `SimpleNamespace`. This is a direct, unavoidable consequence of wiring the CLI to
  actually render+export (the brief's own global constraint requires the full suite to stay green),
  not a drive-by change to unrelated code.

## 6. NOTICE overstated what `docs/licences.md` contains

Changed the one sentence from claiming "the full list of dependencies and their licenses" for both
ecosystems to: "the full Python dependency list (via `pip-licenses`) and an npm dependency
licence-type summary (via `npx license-checker --summary`)" — matching what `docs/licences.md`'s
own "Web (npm) dependency summary" section says about itself. No new files, no new tooling, no
change to the licence-audit process itself (explicitly excluded).

## Test commands run and results

Python:

```
uv run ruff check .                     → All checks passed!
uv run mypy --strict agent_perimeter    → Success: no issues found in 98 source files
uv run pytest                           → 628 passed, 93.87% coverage (floor 75%)
```

(`mypy --strict agent_perimeter` and the bare `uv run pytest` invocation match
`.github/workflows/ci.yml` exactly — checked before running.)

Web (from `web/`):

```
npx tsc --noEmit   → clean, no output
npm run lint       → clean (eslint), no findings
npx playwright test → 64 passed
```

The Playwright suite grew from 62 to 64 (two new `live-scan.spec.ts` tests for item 2; item 3 net
zero — two specs retargeted, no route added or removed since the demo page's tests moved to the
real route). Ran the full suite three times total across the session (once after items 1+2, twice
more after item 3): 64/64, then one run flaked once on an entirely unrelated, untouched test
(`graph.spec.ts`'s "the graph is fully navigable from the keyboard" — a file this fix wave never
touches), which passed both alone and on an immediate full-suite re-run. `playwright.config.ts`'s
own comment documents that this suite shares one dev-server instance across every worker; on this
22-core machine that occasionally produces a single contention-driven timeout under an 11-worker
full run. `.github/workflows/ci.yml`'s CI config already sets `retries: 2` for exactly this reason.
Confirmed this is pre-existing and unrelated to this fix wave by reproducing the same pattern on
the unmodified base commit (`git stash` + rerun) before making any web changes.

## Concerns / deviations from the brief

- Item 2's Playwright test mocks the real (non-fixture) SSE endpoint via `page.route()` — there was
  no existing precedent for testing this screen's non-fixture branch (the page's own docstring
  said outright that no test exercised it), so this is a new pattern for this codebase, not an
  existing one being reused. Kept it to the smallest form that proves the fix: two tests, no shared
  helper, no EventSource shim.
- The natural end of the mocked SSE response can trigger the browser's own EventSource
  auto-reconnect/`error` event (a pre-existing latent gap in the production code's `onError`
  handling — `subscribeToScanEvents` is never explicitly closed on a normal terminal frame, only on
  unmount/retry). This is out of scope for this fix wave and was not touched; it doesn't affect the
  two new tests' assertions either way (the `ErrorState` block renders independently of the
  terminal-summary ternary this fix changes).
- `_stub_census_run()` and the two pre-existing CLI census tests needed updating to keep passing —
  documented above under items 4/5; this is required by wiring the CLI to actually call
  `render_census`/`export_raw`, not scope creep.
- No other files outside the six items were touched. `git diff --stat` against `e4d9564` covers
  exactly: CORS (app.py, .env.example, docker-compose.yml, new test), screen 2 (page.tsx,
  live-scan.spec.ts), the fixture-demo deletion (two deleted files, two retargeted specs), census
  salt/render wiring (models.py, migration, run.py, cli.py, census_report.py docstring, two test
  files), and NOTICE.
