# Task 17 report — compose, clean-machine verification, licence audit, release prep

## Scope boundary — explicit confirmation

Per the dispatch's scope boundary and the pre-flight ruling in `progress.md`:
**Step 8 (flip the repo public, publish to GitHub Pages, tag `v0.1.0`, start
the 90-day embargo clock) was NOT touched.** No `git tag` was run. No `git
push` was run — confirmed by reviewing every git command issued this task
(`add`, `commit`, `status`, `diff`, `log`, one `checkout --` / `update-index`
self-correction on `LICENSE`, `remote -v`, `tag -l`); no push command appears
anywhere. `git remote -v` shows `origin` already points at a real GitHub URL
(`https://github.com/Berakhah/agent-perimeter.git`), but nothing was sent to
it. No repository-visibility or GitHub Pages setting was touched. All four
commits below are local to this worktree/branch (`week4-census-ui`), exactly
like every prior task's commits.

Step 3 (clean-machine verification) was done as an explicit **best-effort
sandbox run**, not a genuine clean-machine run — see below and
`docs/evidence/clean-machine.md`, which states this plainly throughout.

## What was implemented

1. **`GET /api/health`** (`agent_perimeter/api/app.py`) — added TDD-first
   (`tests/api/test_health.py` written and confirmed RED/404 before the
   route existed, then GREEN). Plain liveness probe, no DB round-trip.
2. **`scripts/smoke.sh`** — the brief's script with two fixes, both verified
   by actually running it against a live stack in this sandbox, not by
   static reading:
   - Ruling 2's known stale migration number (`0004` → `0003`), and dropped
     `uv run` in favour of plain `alembic` (the api image is `pip install .`
     based, not a uv-managed venv — `uv` is never installed in it).
   - A second, previously-unflagged bug: the brief's refusal-path assertion
     posts a stdio-shaped target (`"python /server.py"`), but
     `agent_perimeter/api/scans.py::create_scan` classifies the target's
     transport *before* checking for a scope file — a stdio target always
     gets `400 unsupported_target`, never the `422` the assertion wants,
     regardless of whether the scope-file refusal itself works. This was
     caught empirically: running the script as originally written failed
     with `FAIL: active scan without a scope file returned 400, expected
     422`. Fixed by posting an `https://` target instead.
3. **`docker-compose.yml`** restructured from 2 services (`app`, `postgres`)
   to 4 (`db`, `api`, `web`, `fixture`):
   - `db`: `postgres:16-alpine`, named volume, `pg_isready` healthcheck.
   - `api`: builds from the root `Dockerfile`, clears the image's
     `agent-perimeter` CLI entrypoint and runs `alembic upgrade head &&
     uvicorn agent_perimeter.api.app:create_app --factory ...` instead;
     healthcheck against the new `/api/health` route via Python `urllib`
     (no extra OS packages installed for it).
   - `web`: new `web/Dockerfile`, healthcheck via Node's built-in `fetch`.
   - `fixture`: the Week 1 parameterised MCP stdio fixture
     (`tests/fixtures/servers/`), gated behind `--profile demo` — a
     deliberate, documented decision: a stdio server has no "healthy and
     listening" state the way an HTTP service does, and would otherwise
     exit immediately on empty stdin under a bare `docker compose up`.
     Run explicitly with `docker compose --profile demo run --rm fixture`.
4. **`Dockerfile` (api)** — added `COPY alembic.ini ./` and `COPY migrations
   ./migrations`, needed for `alembic upgrade head`/`alembic current` to
   work inside the container at all (neither was previously in the image).
5. **`web/Dockerfile`** (new) — single-stage `node:20-alpine` build
   (`npm ci && npm run build && npm run start`). `NEXT_PUBLIC_API_BASE_URL`
   is threaded through as a build `ARG`/`ENV` since Next.js inlines
   `NEXT_PUBLIC_*` variables at build time, not read at container start —
   without this, the browser-side API client would silently point at the
   wrong origin under compose (`web` on :3000, `api` on :8000 are separate
   origins from the browser's point of view). Marked with a `ponytail:`
   comment: no `next.config.ts` change for `output: "standalone"`, so the
   image carries full `node_modules` — larger than necessary, upgrade path
   noted if image size becomes a real constraint.
6. **`.dockerignore` / `web/.dockerignore`** (new, not originally in the
   Files list) — needed for correctness, not just speed: without
   `web/.dockerignore`, `COPY . .` in `web/Dockerfile` would copy the
   host's own (Windows-built) `node_modules`/`.next` over the freshly
   `npm ci`-installed ones inside the Linux container.
7. **`alembic.ini` + `agent_perimeter/scan_runner.py`** — the DSN's
   hardcoded `localhost` host became `${POSTGRES_HOST}`, using the exact
   same generic env-var-expansion mechanism `migrations/env.py` already
   applies to `${POSTGRES_PASSWORD}`. Needed because the `api` container's
   `alembic upgrade head` must reach the `db` service by Compose service
   name, not the host loopback. `.env.example` defaults `POSTGRES_HOST` to
   `localhost` (matching prior hardcoded behaviour for bare-metal use);
   `docker-compose.yml`'s `api` service overrides it to `db`.
8. **`.env.example`** extended (not recreated) with `POSTGRES_HOST` and
   `NEXT_PUBLIC_API_BASE_URL`, both documented inline.
9. **Licence audit → `docs/licences.md`** (new) — see below.
10. **`LICENSE`** — this file **already existed** (full Apache-2.0 text,
    contrary to my dispatch's "Create" framing — I did not check `git
    status` before writing it the first time, caught this via `git status`
    showing `M` not `??`, reverted my full rewrite with `git checkout --
    LICENSE` and re-applied only the one real fix needed: the template's
    unfilled `Copyright [yyyy] [name of copyright owner]` placeholder →
    `Copyright 2026 Agent Perimeter contributors`. Final diff is 1 line.
11. **`NOTICE`** (new).
12. **`README.md`** (new — confirmed truly absent before writing it,
    ruling 4). Content per the brief's Step 6: what it is, the positioning
    sentence quoted verbatim from `docs/superpowers/specs/2026-08-11-agent-
    perimeter-design.md` ("the first MCP scanner that knows which revision
    of the protocol it is looking at, and the only one that publishes its
    own precision and recall"), the scope-file requirement stated up front
    with a worked example, the `docker compose up` quickstart, the real
    SARIF CI snippet copied from `.github/workflows/ci.yml` (not invented),
    and links to `docs/methodology.md`, `docs/security.md`/`SECURITY.md`,
    `docs/licences.md`, `docs/evidence/`, and the census report — the last
    one honestly points at `docs/census/CHANGELOG.md`, which itself states
    plainly that no run has been published yet, rather than fabricating a
    link to a report that doesn't exist.
13. **`docs/evidence/clean-machine.md`** (new) — see below.
14. **`web/package.json`** — added `"license": "Apache-2.0"`, matching
    `pyproject.toml`. Does *not* change `license-checker`'s summary output
    (see licence audit below) — added for its own correctness regardless.

CLAUDE.md's licence line was confirmed correct (`Apache-2.0`, line 4) and
left untouched, per ruling 6.

## Clean-machine / sandbox verification — honest outcome

**This was not a clean-machine run**, and `docs/evidence/clean-machine.md`
says so in its first paragraph, per the scope boundary. It was a best-effort
run of `cp .env.example .env && docker compose up -d --build --wait &&
./scripts/smoke.sh` **inside this existing development sandbox** (Docker
29.7.2 / Compose v5.4.0 already installed, package registries already warm).

**Outcome: green, on the second attempt.** The first attempt (with the
brief's stdio-shaped refusal probe, before I found and fixed that bug)
failed with `FAIL: active scan without a scope file returned 400, expected
422`. After the fix, all four assertions passed: API liveness, web serving,
the `422` scope-file refusal, and migrations at head (`0003`). All three
always-on services (`db`, `api`, `web`) reached Docker's `healthy` state.
The fourth service (`fixture`, profile-gated) was also built and exercised
directly — sent one `tools/list` JSON-RPC request over stdin, got a correct
response back.

Timing is reported with an explicit caveat that it is not a from-clean-clone
number (Docker's layer cache and the host's package registries were already
warm from earlier builds in the same session); the very first, least-cached
build in this session is separately reported at roughly 3–4 minutes
wall-clock as the more representative (still not authoritative) figure. A
genuine clean-machine run is explicitly recorded as still outstanding.

## Licence audit results

**No AGPL, SSPL, BUSL or non-commercial dependency found**, on either the
Python side (`uv run --with pip-licenses pip-licenses --format=markdown
--with-urls` — `uvx pip-licenses` alone audits its own isolated environment,
not this project's, so `uv run --with` was used instead, per ruling 5) or
the npm side (`cd web && npx license-checker --summary`, 393 packages).

Every dependency not under Apache-2.0/MIT/BSD is flagged explicitly in
`docs/licences.md`, with a runtime-vs-dev-only classification for each:

| Package | Licence | Runtime or dev-only | Status |
|---|---|---|---|
| `hypothesis` | MPL-2.0 | dev-only | already known (earlier task), reconfirmed |
| `@axe-core/playwright` / `axe-core` | MPL-2.0 | dev-only | already known (earlier task), reconfirmed |
| `certifi` (via `httpx`) | MPL-2.0 | **runtime** | new finding this task |
| `psycopg` / `psycopg-binary` | LGPL-3.0-only | **runtime**, direct dependency | new finding this task |
| `pathspec` (via `mypy`/`ruff`) | MPL-2.0 | dev-only | new finding this task |
| `lightningcss` (+ win32 binary, via Tailwind) | MPL-2.0 | dev/build-only | new finding this task |
| `@img/sharp-win32-x64` (optional peer of `next`) | Apache-2.0 AND LGPL-3.0-or-later | runtime-reachable if `next/image` is used (it isn't, currently) | new finding this task |

None of the new findings are AGPL/SSPL/BUSL/non-commercial. The two genuinely
runtime ones (`certifi`, `psycopg`/`psycopg-binary`) are flagged prominently
in `docs/licences.md` with the reasoning for why each is low-risk (MPL-2.0's
copyleft is file-level and explicitly permits combination with a
differently-licensed larger work; LGPL-3.0 permits linking/dynamic use
without relicensing the consumer, and neither package's own source is
modified here). I did not attempt to remove `httpx` or `psycopg` — both are
foundational, essentially unavoidable choices in their category (an HTTPS
client's CA bundle; the project's async-capable Postgres driver), and
neither license is in the "flag and remove" category (AGPL/SSPL/BUSL) this
project's rule actually targets.

One tool quirk worth noting: `license-checker` reports the `web@0.1.0`
package itself as `UNLICENSED` regardless of its declared `license` field —
confirmed empirically (`--excludePrivatePackages` is the only thing that
removes that one entry), because `license-checker` treats any
`"private": true` package this way by design. The `"license": "Apache-2.0"`
field was still added to `web/package.json` for its own correctness; it just
doesn't change that particular tool's report.

## Ten-item DoD walkthrough (brief §12)

1. **`agent-perimeter scan` runs against stdio and HTTP targets, across at
   least two spec revisions, producing SARIF that validates and renders.**
   Closed. Stdio + two-revision coverage:
   `tests/test_cli_integration.py::test_scan_cli_fingerprints_the_real_fixture_at_each_revision`
   (parametrized `2025-11-25`/`2026-07-28`, real containerised fixture, no
   stubbing — skipped only if Docker is unavailable; Docker was available
   throughout this session's runs). HTTP transport coverage:
   `tests/transport/test_streamable_http.py` plus
   `tests/api/test_scans.py` (passive/active scans over an http(s) target
   through the HTTP surface). SARIF schema validation + rendering:
   `tests/report/test_sarif.py::test_output_validates_against_the_2_1_0_schema`
   and `.github/workflows/ci.yml`'s `github/codeql-action/upload-sarif@v3`
   step, which actually uploads the golden SARIF to GitHub code scanning on
   every push.
2. **Every check maps to a CWE and at least one published taxonomy entry,
   cited in the report output.** Closed.
   `tests/checks/test_all_checks.py::test_every_check_cites_a_resolvable_taxonomy_entry`,
   `::test_every_check_cites_at_least_one_approved_scheme`,
   `::test_every_check_declares_a_well_formed_cwe`,
   `::test_every_check_s_cwe_is_registered` — all four enumerate the real
   `ALL_CHECKS` registry, not a sample.
3. **Active probes refuse to run without a valid scope file — with a test
   proving it.** Closed. `tests/model/test_scope.py` (the refusal logic
   itself) and `tests/api/test_refusal.py` (the HTTP surface, including
   `test_the_api_and_the_cli_refuse_on_the_same_condition`, which greps the
   API module's own source to prove one shared authorisation function, not
   two implementations). `scripts/smoke.sh` (this task) asserts the same
   thing end to end against a running compose stack — verified green in
   this sandbox.
4. **All stdio launches are containerised — with a test proving
   containment.** Closed.
   `tests/transport/test_stdio.py::test_docker_args_enforce_every_containment_control`
   plus siblings in the same file (`test_hardened_seccomp_is_the_default`,
   `test_allow_network_is_explicit_and_off_by_default`,
   `test_zero_timeout_is_rejected`, `test_hard_timeout_actually_kills_the_container`).
5. **Capability graph renders, with derivation method visible per edge
   through the provenance rail.** Closed.
   `web/tests/graph.spec.ts::every edge exposes its derivation`,
   `::a probe-derived edge is visually distinct from a description-derived one`,
   `::a text alternative lists every node and edge` — all passed in this
   task's Playwright run (62/62 passed).
6. **Precision and recall measured against the fixture corpus and published
   in `docs/methodology.md`.** Closed. The "Measured precision and recall"
   table in `docs/methodology.md`, regenerated and confirmed fresh in this
   task (`uv run python -m agent_perimeter.eval.run --write
   docs/methodology.md` produced no diff — `git diff --exit-code` passed),
   matching the CI step that fails the build if it ever goes stale.
7. **A passive public-registry scan report published, with sample,
   population, method, collection window, term definitions, raw data, and
   analysis script.** **NOT closed.** `docs/census/CHANGELOG.md` states
   plainly, as of this task: "No census has been published yet," naming two
   concrete blockers (unverified SDK version floors; Tier 3 live-discover
   not yet wired into `run_census`). Per the task dispatch's own note, no
   live Tier-3 census request has ever been sent in this project — running
   one is a real-world action with its own consequences (an actual embargo
   clock, actual maintainer contact) and is out of this task's scope for
   the same reason Step 8 is. `analysis/census_analysis.py` exists and is
   tested (`tests/report/test_census_analysis.py`) but has no real data to
   reproduce figures from yet. README.md's link to this item points at the
   changelog rather than a fabricated report.
8. **`docs/security.md` contains the coordinated-disclosure policy.**
   Closed. `docs/security.md` (read in full this task) carries all the
   required sections: reporting, what happens when something is found,
   embargo (90 days), right of reply, secrets handling, what's published,
   digest-salt release. `tests/docs/test_security_policy.py` (run in CI as
   "Validate security policy structure") is the test proving it. `SECURITY.md`
   carries the matching contact for vulnerabilities in the tool itself.
9. **Web UI passes axe with zero serious/critical, works keyboard-only,
   prints correctly.** Closed. `web/tests/a11y.spec.ts` (24 tests across 6
   screens: axe, keyboard operability, focus rings, 375px) and
   `web/tests/print.spec.ts` (4 tests: no interactive chrome, severity
   survives greyscale, no split rows, census report prints intact) — all
   28 passed in this task's Playwright run.
10. **`docker compose up` reproduces everything on a clean machine.**
    **Not closed as a genuine clean-machine claim** — closed only as a
    best-effort sandbox verification, per this task's explicit scope
    boundary. `docs/evidence/clean-machine.md` (this task) records a green
    run of `docker compose up -d --wait && ./scripts/smoke.sh` inside the
    existing development sandbox, states plainly throughout that this is
    not a fresh-VM run, and states that a genuine clean-machine
    verification is still outstanding, to be run before Step 8's
    (out-of-scope) publish actions.

**Summary: 8 of 10 fully closed with named evidence. Two (7 and 10) are
explicitly and honestly not fully closed** — both for the same underlying
reason (a real-world action — a live Tier-3 census run; a genuine
clean-machine VM run — that this task's scope boundary correctly keeps out
of an agent's hands without the human partner's direct involvement).

## Final DoD sweep results

- `uv run pytest --cov=agent_perimeter --cov-report=term-missing`:
  **619 passed**, coverage **93.88%** (floor 75%).
- `uv run mypy --strict agent_perimeter`: **Success, no issues, 98 files.**
- `uv run ruff check .`: **All checks passed.**
- `uv run ruff format --check .`: **9 pre-existing files** would be
  reformatted (`agent_perimeter/census/artifacts.py`,
  `agent_perimeter/census/sample.py`, `analysis/census_analysis.py`,
  `tests/census/test_artifacts.py`, `tests/census/test_run.py`,
  `tests/census/test_tier3.py`,
  `tests/checks/descriptions/test_imperative_and_mismatch.py`,
  `tests/report/factories.py`, `tests/transport/test_stdio.py`) — **none of
  these are files this task touched.** Matching Task 16's precedent,
  disclosed rather than silently fixed (this task's own scope is compose/
  licensing/release prep, not a drive-by formatting pass over unrelated
  files). One genuinely self-caused formatting violation *was* fixed: my
  first edit to `agent_perimeter/scan_runner.py`'s `DEFAULT_DATABASE_URL`
  kept the pre-existing parenthesised-multiline form, which `ruff format`
  wants collapsed to one line regardless of resulting length (verified: the
  original, shorter, pre-edit string was already in that canonical
  single-line form) — fixed in place before committing.
- `npx tsc --noEmit` (web/): clean, no output.
- `npm run lint` (web/): clean, no warnings.
- `npx playwright test` (web/): **62 passed**, 0 failed.

## Files changed (against the pre-task HEAD, `f4477ea`)

17 files, +631/-17:

- New: `.dockerignore`, `web/.dockerignore`, `web/Dockerfile`,
  `scripts/smoke.sh`, `tests/api/test_health.py`, `NOTICE`, `README.md`,
  `docs/evidence/clean-machine.md`, `docs/licences.md`.
- Modified: `docker-compose.yml`, `Dockerfile`, `alembic.ini`,
  `agent_perimeter/scan_runner.py`, `agent_perimeter/api/app.py`,
  `.env.example`, `web/package.json`, `LICENSE` (1-line fix only).

Committed as 4 local commits on `week4-census-ui`:
`88b1d78` (health route + test), `89573da` (compose restructure + smoke
script fixes), `68a84ea` (executable-bit fix for smoke.sh — Git Bash's
`chmod +x` didn't propagate to the git index on this Windows sandbox in the
prior commit; caught and fixed before this report), `e4d9564` (licence
audit, LICENSE/NOTICE/README, clean-machine record). **None pushed.**

## Self-review findings

- Caught and fixed mid-task: `LICENSE` already existed — my first pass
  overwrote it with a cosmetically-different full rewrite instead of
  checking `git status` first. Reverted via `git checkout -- LICENSE`
  (presented under the Fact-Forcing Gate before running, as it's a
  destructive-class command) and reapplied only the one real fix.
- Caught and fixed mid-task: `scripts/smoke.sh` lost its executable bit
  between `chmod +x` and `git commit` on this Windows/Git-Bash sandbox —
  fixed with `git update-index --chmod=+x` in a small follow-up commit
  rather than an amend.
- Caught and fixed mid-task: `docs/licences.md`'s first draft claimed
  adding `"license"` to `web/package.json` fixed the `UNLICENSED`
  self-entry in `license-checker`'s report; re-running the tool afterward
  showed it didn't (confirmed the real cause — `license-checker`'s
  `"private": true` handling — via `--excludePrivatePackages`), and the
  doc was corrected before committing rather than left overstating what
  the fix actually did.
- Found and fixed a real bug in the brief's own literal smoke-script text
  (the stdio-target-against-an-http-only-endpoint refusal-path bug,
  detailed above) — caught only by actually executing the script against
  a live stack, not by reading it.
- The `web/Dockerfile`'s single-stage build (no `next.config.ts`
  `output: "standalone"` change) is marked with an explicit `ponytail:`
  comment naming the tradeoff (larger image) and the upgrade path.
- Did not attempt to fix the 9 pre-existing `ruff format` drift files
  outside this task's own changes — disclosed instead, per precedent.
- Did not attempt to run a live Tier-3 census (DoD item 7) or a genuine
  clean-machine VM (DoD item 10) — both are real-world actions outside
  this task's scope boundary, and both are disclosed as open rather than
  quietly claimed closed.

## Concerns for the human partner

- **DoD items 7 and 10 are the two genuine gaps left in Week 4**, and both
  require an action outside what an agent should take unilaterally: a live
  Tier-3 census run (real network requests to real third-party MCP
  servers, starting a real embargo clock) and a genuine clean-machine VM
  verification. Both are prerequisites the brief itself lists before Step
  8's publish actions.
- `docs/licences.md` surfaces two new runtime (not dev-only) non-Apache/
  MIT/BSD dependencies (`certifi` MPL-2.0, `psycopg`/`psycopg-binary`
  LGPL-3.0) that weren't previously on record anywhere in this plan. I
  assessed both as low-risk and did not remove them (removing `httpx` or
  the Postgres driver would be disproportionate to what CLAUDE.md's rule
  actually targets — AGPL, specifically), but this is a judgement call the
  human partner may want to weigh in on before any external legal review.

Full report (this file): `.superpowers/sdd/2026-08-11-agent-perimeter-week4-census-ui/task-17-report.md`
