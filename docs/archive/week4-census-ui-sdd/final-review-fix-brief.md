# Final whole-branch review — fix wave (post Task 17)

All 17 tasks in the plan are complete and merged into this branch (commits `14a5b24..e4d9564`).
Per `superpowers:subagent-driven-development`'s Final Review step, three independent reviewers
were dispatched against the whole branch. Their findings are synthesized below, verified against
the real code at `e4d9564` (not assumed from the review text) before this brief was written.

Two items from the original synthesis are **excluded from this fix wave on purpose** — they are
decisions for the human partner, not code fixes, and must not be silently resolved here:
- No auth/SSRF gating on `/api/*` (already a disclosed, human-confirmed known gap from Task 9's
  ledger entry — do not add auth or target restrictions in this fix wave).
- The licence-audit process itself only having been run on Windows, missing Linux-only runtime
  deps (`uvloop` etc.) that install in the deployed image — a process/tooling gap, not a bug to
  patch in application code.

Do not touch either of those. Everything below IS in scope. Fix all six, in one PR-sized diff.

## 1. [Critical] No CORS on the FastAPI app

`agent_perimeter/api/app.py`'s `create_app()` has no `CORSMiddleware`. `docker-compose.yml` runs
`web` on `:3000` and `api` on `:8000` as separate services; `web/src/lib/api.ts`'s `fetch()`/
`EventSource` calls go directly to `NEXT_PUBLIC_API_BASE_URL` (`http://localhost:8000` per
`.env.example`) — a cross-origin call from the browser's perspective. Right now `docker compose up`
+ opening the UI + submitting a scan fails outright: the browser blocks the response. This breaks
the exact flow the README and the Definition of Done present as the deliverable.

**Fix:** add `from fastapi.middleware.cors import CORSMiddleware` to `app.py` and wire it in
`create_app()` (after `app = FastAPI(...)`, before the routers are included):

- Allowed origins: read from a new `AP_CORS_ORIGINS` env var, comma-separated, defaulting to
  `http://localhost:3000` (matches this repo's own dev/compose port). Split and strip on commas;
  empty string should not create a `[""]` origin list.
- `allow_methods=["*"]`, `allow_headers=["*"]`.
- `allow_credentials=False` — this API has no cookies/auth (see the excluded SSRF/auth item
  above), so there is nothing to carry credentials for; `False` is also required by the CORS spec
  to combine with a wildcard-shaped origin config, so don't set it `True` without a real reason.
- Add `AP_CORS_ORIGINS=http://localhost:3000` to `.env.example` with a one-line comment (mirror the
  existing comment style there), and pass it through in `docker-compose.yml`'s `api` service
  `environment:` block the same way `AP_CONTACT_URL` already is
  (`AP_CORS_ORIGINS: ${AP_CORS_ORIGINS:-http://localhost:3000}` — give it an inline default in
  compose so a bare `docker compose up` with no `.env` edits still works).

**Test:** a test using FastAPI's `TestClient` asserting an `OPTIONS`/actual request from
`Origin: http://localhost:3000` gets back `access-control-allow-origin: http://localhost:3000`,
and one from an unrelated origin (e.g. `http://evil.example`) does not. Place it alongside the
existing API tests (check `tests/api/` for the existing layout and follow it).

## 2. [Important] Screen 2 (live scan) claims "No findings" unconditionally

`web/app/scans/[id]/page.tsx:191-204` renders `EmptyState title="No findings for the checks that
ran"` the instant the terminal SSE frame arrives (`terminalEvent !== null`), regardless of whether
the scan actually produced findings. `ScanTerminalEvent` (`web/src/lib/api.ts`) carries no findings
count — only `completed`, `total`, `skipped`. A scan that finds a critical vulnerability currently
tells the user "No findings" for a moment before they click through to the findings screen. This is
exactly the false-reassurance failure mode CLAUDE.md's Copy rules exist to prevent in a security
tool ("Empty findings reads... never 'You're secure!'" — the inverse failure, claiming empty when
it isn't, is the same class of harm).

`getScan(id)` (`web/src/lib/api.ts:129`) already returns `ScanStatus.findings_count?: number`.

**Fix, real (non-fixture) path only:** once the terminal frame arrives, call `getScan(id)` and
branch on `findings_count`:
- `findings_count === 0` -> today's `EmptyState` with the existing copy, unchanged.
- `findings_count` is a positive number -> a different summary stating the count and linking to
  the findings screen (the "View findings for this scan" link at the top of the page already
  exists — reuse or reference it), e.g.
  `${findings_count} finding${findings_count === 1 ? "" : "s"} — see below.` Do not invent
  upbeat/reassuring copy; state the fact.
- `findings_count` is `undefined` (fetch failed, or the field is genuinely absent) -> do **not**
  default to the "No findings" copy, since that's a false claim if a fetch simply failed. Render
  something that states the count is unknown, matching this codebase's existing "absence reads as
  unknown, not a negative claim" convention (see `ConformanceStrip`'s `revision_claimed` handling
  for the established pattern/tone).

**Fixture mode (`?fixture=streaming|degraded|deterministic`):** these fixtures replay canned
`ScanEvent[]` sequences with no backing `getScan` to call. Check `web/app/scans/[id]/fixtures.ts`
and whatever spec file currently asserts on this screen's terminal copy (grep `tests/` for
`scans/1` or `scan-setup`/`live-scan` spec names) before changing anything, so existing assertions
keep passing. If a fixture scenario is meant to represent a clean run, it should keep showing "No
findings"; if none of the three represents an unclean run, either add a `findingsCount` alongside
the fixture's event array (threaded through the same replay path used for the real count) or make
the minimal change that keeps the real-path fix honest without breaking fixture tests. Use
judgement — the binding requirement is "real scans never claim zero findings when there are any,"
not a specific fixture shape.

**Test:** extend or add a Playwright spec exercising `/scans/{id}` (real path, mocked backend
response, or however this codebase's existing tests fake the non-fixture path — check
`web/tests/` for precedent) asserting that a non-zero `findings_count` does not render "No findings
for the checks that ran".

## 3. [Important] `/findings` fixture-demo route ships as a real, unauthenticated production route

`web/app/findings/page.tsx` (distinct from the real `/scans/[id]/findings` screen) is Task-10
token-verification scaffolding, kept alive only because `web/tests/tokens.spec.ts` (2 `goto` calls,
lines 4 and 15) and `web/tests/provenance-rail.spec.ts` (1 `goto` call, line 8) still target
`/findings?fixture=mixed` instead of the real screen. It renders fabricated "critical"/"high"
severity findings (e.g. "Path traversal via `read_file` tool") with zero on-screen indication it's
fixture data, reachable by anyone who finds the URL — a real credibility risk for a product whose
entire pitch is trustworthy, reproducible findings.

Verified: `web/tests/findings.spec.ts` and `web/tests/a11y.spec.ts` already exercise the real route
`/scans/1/findings?fixture=mixed`, which renders through the same `FindingsTable` component — so
retargeting loses no coverage.

**Fix:**
1. In `web/tests/tokens.spec.ts`, change both `page.goto("/findings?fixture=mixed")` calls (lines 4
   and 15) to `page.goto("/scans/1/findings?fixture=mixed")`.
2. In `web/tests/provenance-rail.spec.ts`, change the one `page.goto("/findings?fixture=mixed")`
   call (line 8) to `page.goto("/scans/1/findings?fixture=mixed")`. Confirm the real route's
   `mixed` fixture renders a `data-testid="claim"` element and a `data-testid="provenance-rail"`
   element (Task 13's `FindingsTable`/`FindingRow` wiring should already provide both) — if the
   `mixed` fixture on the real route doesn't happen to include a Claim-activatable row, pick
   whichever fixture key on the real route does (check `web/app/scans/[id]/findings/fixtures.ts` or
   equivalent) rather than inventing a new one.
3. Delete `web/app/findings/page.tsx` and `web/app/findings/ProvenanceDemo.tsx` (confirm nothing
   else imports `ProvenanceDemo` before deleting it — grep first).
4. Run the full Playwright suite after this change; both retargeted specs and everything else must
   still pass.

## 4 & 5. [Important] `census --out` never renders the report, and the per-run digest salt can never be reproduced

These two are fixed together — both live on the same code path (`agent_perimeter/cli.py`'s
`census()` command -> `agent_perimeter/census/run.py::run_census()` ->
`agent_perimeter/report/census_report.py`).

**4a — dead CLI output.** `cli.py`'s `census()` command (`agent_perimeter/cli.py:260-304`) calls
`run_census()`, creates the `--out` directory, and echoes four summary lines — it never calls
`render_census()` or `export_raw()` (both in `agent_perimeter/report/census_report.py`, both pure
functions with no CLI dependency). Today, the only callers of `render_census`/`export_raw` outside
the test suite are `analysis/render_web_fixtures.py` (a dev script) and `analysis/census_analysis.py`.
The CLI genuinely cannot produce the published census report end-to-end as shipped.

**4b — the salt bug `export_raw`'s own docstring already documents.** `run_census()`
(`agent_perimeter/census/run.py:94-121`) generates `salt = secrets.token_bytes(32)` (line 111),
uses it to compute each `CensusRecord.coords_digest` at collection time, then **discards it** —
there is a `ponytail:` comment on lines 108-110 saying exactly this, added when `export_raw` was
built and needed a salt but had none to reuse. `census_report.py::export_raw`'s own `_digest_for`
docstring (lines 175-183) already states the resulting inconsistency plainly: whatever salt
`export_raw` is called with will **never** match the salt baked into the DB's `coords_digest`
column, because that one "cannot be reproduced later." This breaks the plan's "publish the salt
after the 90-day embargo, so anyone can recompute and verify `coords_digest`" model — there is
nothing durable to publish.

**Fix:**
1. `agent_perimeter/db/models.py`: add `salt: Mapped[bytes] = mapped_column(nullable=True)` to
   `CensusRun` (nullable — this is pre-release data, no backfill story needed, and nullable avoids
   forcing a default on a security-adjacent value).
2. New Alembic migration `migrations/versions/0004_census_run_salt.py` (`down_revision = '0003'`,
   `revision = '0004'`, following `0003_census.py`'s exact style/imports) adding that one nullable
   `LargeBinary` (or dialect-appropriate bytes) column to `census_run`.
3. `agent_perimeter/census/run.py::run_census()`: after generating `salt` (line 111), also set
   `run.salt = salt` so it's persisted on the `CensusRun` row (one line). Delete the now-resolved
   `ponytail:` comment on lines 108-110 (the gap it named is closed) and replace it with nothing, or
   a short factual note that the salt is now persisted on `CensusRun.salt`.
4. `agent_perimeter/cli.py::census()`: after `run_census()` returns `run`, inside the still-open
   `session`, query the persisted `CensusRecord` rows for `run.id` (see
   `analysis/render_web_fixtures.py` for the `render_census(run, records)` call pattern, and
   `census/run.py`'s own aggregation helpers for how records are queried by `census_run_id`
   elsewhere in this codebase), then:
   - call `render_census(run, records)` and write the result to `out / "census.html"`
   - call `export_raw(run, records, salt=run.salt, out=out)` — passing the now-persisted salt, not
     a fresh one, so this export's digests match the DB's `coords_digest` column by construction
   - echo the written paths (mirror the existing `typer.echo(...)` style in that function)
   Do this before the session closes (same "read while the session is still open" constraint the
   existing code already comments on at lines 295-297).

**Test:** a CLI test (Typer's `CliRunner`, or whatever pattern `tests/` already uses for `cli.py` —
check for existing CLI tests first) asserting `agent-perimeter census --out <tmpdir>` produces
`census.html` and `records.csv` in that directory, and a unit test asserting the CSV's digest for a
given record matches `CensusRecord.coords_digest` for that same record when both are computed with
`run.salt` (proving the mismatch is actually closed, not just that files exist).

## 6. [Important] NOTICE overstates what `docs/licences.md` actually contains

`NOTICE` says: *"see docs/licences.md (Python dependencies, via `pip-licenses`) and `web/` (npm
dependencies, via `npx license-checker`) for the full list of dependencies and their licenses."*
There is no per-package npm list anywhere in `web/` or elsewhere — `docs/licences.md`'s own "Web
(npm) dependency summary" section is explicitly generated via `license-checker --summary`
(license-type counts only, e.g. "MIT: 330"), not a full per-package list, and it lives in
`docs/licences.md`, not in `web/`. This is a real documentation-accuracy gap, not a licensing
compliance problem (no AGPL/SSPL found either side).

**Fix (smallest correct change — do not add new tooling or generate a new file for this):** edit
`NOTICE` to describe what's actually there. Something like: *"see docs/licences.md for the full
Python dependency list (via `pip-licenses`) and an npm dependency licence-type summary (via `npx
license-checker --summary`)."* Keep it one sentence, factual, no new files, no new scripts.

## Global constraints (apply to all six)

- Python: `ruff check`, `mypy --strict`, and the full `pytest` suite must stay green.
- Web: `npx tsc --noEmit`, `npm run lint`, and the full Playwright suite (`npm test` or whatever
  script name `web/package.json` uses) must stay green — 62/62 passing today, should still be
  62+/62+ after (net new tests from items 1, 2, 4/5 are additions, not replacements).
- Do not touch the two excluded items (auth/SSRF gating, licence-audit Linux blind spot).
- Do not invent scope beyond what's specified above — this is a fix wave for named, verified
  findings, not a chance to refactor adjacent code.
- Follow this repo's existing conventions (copy tone, test file placement, migration style) rather
  than introducing new ones.

## Report contract

Write your report to
`.superpowers/sdd/2026-08-11-agent-perimeter-week4-census-ui/final-review-fix-report.md` in this
worktree. Commit your work (conventional commit style, matching this branch's existing history —
`git log --oneline` to see the pattern). Return: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT
/ BLOCKED), the commit range, a one-line test summary per suite (Python + web), and any concerns.
