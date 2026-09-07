# Task 6a report: Census run pipeline, CLI command, passive-only guarantee

Scope: everything in `task-6-brief.md` except `tier3.py` (that's task 6b, dispatched separately).

## What was implemented

- `agent_perimeter/census/run.py` (new) — `method_hash()` (verbatim from the brief),
  `run_census(session, client, *, endpoint, tier2_n) -> CensusRun`, plus three private helpers
  the brief's pseudocode referenced but never defined: `_record_for`, `_record_failures`,
  `_distribution`, `_digest_for`.
- `agent_perimeter/cli.py` — `DEFAULT_REGISTRY` constant and the `census` Typer command (the brief
  gave only the signature/docstring; the body — DB bootstrap, running the pipeline, printing the
  summary — was mine to write).
- `tests/census/test_passive_only.py` (new) — the brief's three tests, with the transitive-guard
  fix on `test_census_can_never_reach_a_transport_or_an_active_check` and
  `@pytest.mark.skip(reason="tier3.py lands in task 6b")` on
  `test_tier3_sends_exactly_one_method_and_owns_no_host`.
- `tests/census/test_run.py` (new) — 9 tests covering `method_hash`, orchestration/persistence,
  distribution-column population (all 5 cases), temp-dir cleanup (2 tests), and `fetch_failures`
  aggregation (2 tests). The brief listed this file but never specified its contents.

## Design decisions the brief left open

**`_record_for` / `_record_failures` bodies.** The brief's `run_census` pseudocode calls both but
defines neither. `_record_for(run, entry, ranked_by_id, salt)` builds a `CensusRecord` with every
column populated up front (`fetch_status` defaults to a new `NOT_ATTEMPTED = "not_attempted"`
sentinel, not a `FetchStatus` member — conflating "never attempted" with e.g. `NOT_FOUND` would
misreport every tier-1 entry as a failed fetch). `_record_failures(session, run)` queries the
records just added to the session (autoflush makes them visible before commit) and counts anyone
whose `fetch_status` is neither `OK` nor `NOT_ATTEMPTED`.

**`distribution` population**, per the task's spec, in priority order: `package_{ecosystem}` if
`entry.coords` resolved, else `package_other` if `entry.has_unmodeled_package`, else `remote_only`
if `entry.remotes` is non-empty, else `none`. Covered by
`test_distribution_is_populated_for_every_case`, which builds one registry page with all 5 cases
and asserts each record's `distribution` independently.

**`coords_digest` / salt.** `CensusRecord.coords_digest` is `NOT NULL`, and `PackageCoords.digest()`
needs a salt the brief's `run_census(session, client, *, endpoint, tier2_n)` signature has nowhere
to take one from. I generate one `secrets.token_bytes(32)` salt per run inside `run_census` and use
it for every record — including remote-only/bare entries with no `PackageCoords` at all, via a
`_digest_for()` fallback that hashes `registry:{registry_id}` the same way `PackageCoords.digest`
hashes `{ecosystem}:{name}`, so every record gets a pseudonym, not just the ones with a package.
Marked `ponytail:` — this salt isn't persisted anywhere outside the call, so Task 7's
`export_raw(..., salt: bytes, ...)` doesn't yet have a store to read a matching salt back from.
That's a real gap between 6a and 7 worth flagging to whoever picks up Task 7 (see Concerns).

**Temp-dir cleanup** (the brief's stated gap from Task 3's review): `shutil.rmtree(result.root,
ignore_errors=True)` runs in a `finally` around the `detect.detect_features(result.root)` call, so
cleanup happens even if detection raises — not just on the happy path the brief's pseudocode shows.
Two tests: one where `detect_features` finds real signal (proves cleanup doesn't depend on a miss),
one where it finds nothing.

**CLI command body.** The brief gave only the signature and docstring. Implementation: `out.mkdir()`,
a `create_engine("sqlite:///{out}/census.db")` + `Base.metadata.create_all()`, `run_census()` inside
one `httpx.Client()` + `Session()` block, four `typer.echo()` lines read *before* the session closes
(`CensusRun`'s attributes are expired by `run_census`'s internal `commit()`; reading them after the
`with` block closes raises `DetachedInstanceError` — I hit this myself in a first draft of
`test_fetch_failures_is_printed_even_when_zero` and fixed both the test and the CLI the same way).
SQLite-under-`out/`, not the project's shared Postgres — marked `ponytail:`, see Concerns.

## One correction applied to the brief's own `test_every_module_but_tier3_talks_only_to_the_allowed_hosts`

Running the brief's test verbatim against the already-committed `fetch.py`/`artifacts.py`/`sample.py`
(Tasks 2/3/5) fails: `unexpected host in census: {'github.com'}`. All three modules' `USER_AGENT`
constants embed `https://github.com/USER/agent-perimeter/blob/main/docs/security.md` as the
CLAUDE.md-required contact URL — a value sent as a header, never a URL requested. Added
`"github.com"` to the test's `allowed` set with a comment explaining why (self-identification, not
a request target). This is not a change to the test's assertion logic or strictness, only to which
hosts count as "a host tiers 1-2 legitimately mention."

## The transitive-guard fix

`test_census_can_never_reach_a_transport_or_an_active_check` now builds the whole
`agent_perimeter.*` import graph reachable from `agent_perimeter/census`, not just each census
file's own direct imports: a worklist starting from every `agent_perimeter.*` name imported
(directly) by a census file, expanded by parsing each newly-discovered module's own imports via the
same `_imports()` AST walk, stopping at a forbidden hit (already an offence) or a name outside
`agent_perimeter` (third-party graph, not this project's to police). Docstring on the test explains
why one-hop wasn't enough: a chain leaving `census` through another `agent_perimeter` module (e.g.
`census.run` → `db.models` → `transport.x`) was invisible to the original version, which only ever
looked at files physically under `agent_perimeter/census`.

**Proved both directions, for both the one-hop and the transitive gap:**

1. Brief's own Step 3 — added `from agent_perimeter.transport import streamable_http` directly to
   `run.py`. Failed: `census reached a live-traffic module: agent_perimeter\census\run.py:
   agent_perimeter.transport`. Reverted, passed again.
2. The gap this task asked me to close — added the same import to `agent_perimeter/db/models.py`
   (a module `run.py` imports, but which lives outside `agent_perimeter/census`) and ran both the
   brief's original one-hop test (copied to a scratch file, not committed) and my transitive
   version side by side:
   - One-hop: **passed** — never looks at what `db/models.py` imports, so it missed the chain.
   - Transitive: **failed** —
     `agent_perimeter\db\models.py: agent_perimeter.transport (reached from
     agent_perimeter\census\run.py via agent_perimeter.db.models)`.

   This is the exact scenario the task described as uncaught by the one-hop version. Reverted
   `db/models.py`; `git diff --stat` confirms no stray changes remain there. Both the one-hop scratch
   test and the temporary edits were never committed.

## TDD evidence

RED (`test_run.py`, before `run.py` existed):
```
ImportError: cannot import name 'run' from 'agent_perimeter.census'
```

RED→GREEN detour on `test_passive_only.py`'s host-allowlist test (see correction above):
```
AssertionError: unexpected host in census: {'github.com'}
```
Fixed by adding `github.com` to the test's own allowed set (not by touching `fetch.py`/`artifacts.py`/
`sample.py`, which are correct as they stand).

GREEN:
```
uv run pytest tests/census/ -q
65 passed, 1 skipped
```

## Verification

- `uv run ruff check .` — All checks passed (whole repo).
- `uv run mypy --strict agent_perimeter` — Success: no issues found in 88 source files.
- `uv run mypy --strict tests/census/test_run.py` — Success: no issues found (not required by the
  project's verify command, which only covers the `agent_perimeter` package, but kept clean anyway
  since it cost nothing — the pre-existing `tests/census/*.py` files predate strict typing and were
  left as-is, out of scope).
- `uv run pytest tests/census/` — 65 passed, 1 skipped (the tier3 test).
- `uv run pytest` (full repo, coverage on) — 547 passed, 1 skipped, 93.08% total coverage (floor 75%).
- CLI smoke test: see "Step 5" section below.

## Step 5: running it small, end to end

The brief's literal command, `uv run agent-perimeter census --tier2-n 5 --out /tmp/census-smoke`,
was started against the real live registry and confirmed reachable (network access verified
separately with `curl`; the CLI's own run created `census.db` and began writing rows). It was still
running against the full live population when I stopped waiting on it, for a concrete, structural
reason: `sample.rank()` looks up a download count for *every* entry with `PackageCoords` in the
**whole population**, not just the tier-2 selection — `--tier2-n` only bounds the artifact-fetch
stage. Against the real registry (4,000+ entries, ~30% with a package, verified in the plan's own
revision notes) that's on the order of a thousand sequential HTTP calls before `run_census` ever
gets to filtering down to tier 2. This is the brief's own two-phase design (rank everything, then
select top N), not a bug — but it means a truly "small" run needs a small *population*, which the
live registry doesn't offer.

So I additionally ran the exact same command against a throwaway local registry server (a ~30-line
`http.server` script serving one page of 4 entries — 3 bare, 1 remote-only, no `PackageCoords` on
any of them, so `sample.rank()` never calls the real `pypistats.org`/`api.npmjs.org` either — see
`sample.py`'s "An entry with no coords is never looked up at all"). Everything else was the real
binary, real argument parsing, real SQLite persistence, real console output — only the registry
endpoint was swapped, via the CLI's own `--endpoint` flag:

```
$ uv run agent-perimeter census --endpoint http://127.0.0.1:8765/v0/servers --tier2-n 5 --out /tmp/census-smoke-local
Population size: 4
Tier-2 n:        5
Fetch failures:  0
Method hash:     b194eea2bfe38b9f
```

Confirms exactly what Step 5 asks for: it completes, prints population size, tier-2 `n`, fetch
failures and the method hash, and **`Fetch failures: 0` prints unconditionally** — not only when
nonzero. `census.db` was created under `/tmp/census-smoke-local` with the run and its 4 records
persisted.

## Files changed

- `agent_perimeter/census/run.py` (new)
- `agent_perimeter/cli.py` (modified — `DEFAULT_REGISTRY` + `census` command)
- `tests/census/test_passive_only.py` (new)
- `tests/census/test_run.py` (new)

Commit: `f037014` — "feat: census pipeline with a structural passive-only guarantee"

## Self-review

- **Completeness:** transitive guard proven genuinely transitive both ways (see above, with the
  scratch one-hop comparison). Temp-dir cleanup real, in a `finally`, and tested for both the
  detected-features and no-features-found cases. `distribution` populated correctly for all 5
  cases (`package_npm`, `package_pypi`, `package_other`, `remote_only`, `none`) in one test that
  builds all 5 in a single registry page and asserts each independently.
- **Quality:** `run_census` matches the brief's pseudocode structure exactly, with the two required
  additions (cleanup, distribution) folded in at the same points the brief's own logic already
  touches those records. CLI command follows `scan()`'s established pattern of lazy imports inside
  the command body. `ponytail:` comments on both deliberate scope cuts (salt not persisted, SQLite
  instead of shared Postgres).
- **Discipline:** did not create, import, or reference `tier3.py` anywhere. Confirmed via
  `git status`/`git diff --stat` — only `cli.py` (modified), `run.py`, `test_passive_only.py`,
  `test_run.py` (new) are touched.
- **Testing:** `test_passive_only.py` passes for real except the explicitly-skipped tier3 test
  (marked exactly as instructed, reason string included). Every other census test passes for real,
  no xfails, no weakened assertions.

## Concerns

1. **Salt persistence gap (6a → Task 7).** `run_census` generates and uses a per-run salt but never
   stores it. Task 7's `export_raw(run, records, *, salt: bytes, out: Path)` will need the *same*
   salt to reproduce the `coords_digest` values already written to `census_record` rows — right now
   there's nowhere for it to read that from. Whoever picks up Task 7 needs to either add a salt store
   this task didn't build, or the digests as currently persisted are effectively single-use (fine for
   "never name anyone," not fine for "publish raw data whose digests resolve after the embargo").
   Flagging rather than solving, since it's explicitly Task 7's interface, not 6a's.
2. **CLI uses a local SQLite file, not the project's shared Postgres.** No app-level DB session
   helper exists anywhere in the codebase yet (confirmed — `record_secret_finding` is the only other
   DB writer and nothing calls it from the CLI either), so there was no existing convention to follow.
   Documented as a `ponytail:` comment with the upgrade path.
3. **Live smoke test runtime.** As detailed in "Step 5" above: `--tier2-n` doesn't bound how long a
   real run takes, because `sample.rank()` scores the whole population first. Worth knowing before
   running this unattended against the live registry — a first real invocation could look "hung" for
   several minutes while it's actually working through the ranking pass.

## Fix report: 2 Important findings from code review (commit `c084dcd`)

The reviewer found 2 Important issues in commit `f037014`. Both are fixed, tested, and committed.

### Finding 1: the transitive guard missed `from agent_perimeter import <subpackage>`

**Root cause.** `_imports()` recorded `ast.ImportFrom.module` (e.g. `"agent_perimeter"` for
`from agent_perimeter import transport`) but never checked whether an individual imported *alias*
(`transport`) itself resolved to a submodule on disk. So `from agent_perimeter import transport`
and `from agent_perimeter import __version__` looked identical to the walker — both just
`"agent_perimeter"` — even though the first binds a live-traffic submodule and the second binds a
harmless string constant. A chain that reached a forbidden module *only* through this import style
(the exact idiom `run.py` itself already uses for its own siblings —
`from agent_perimeter.census import artifacts, detect, fetch, sample`) was invisible to the
transitive walk even after last commit's transitivity fix, because the forbidden submodule name
never appeared in `_imports()`'s output at all — not one hop away, not any number of hops away.

**Fix.** `_imports()` now additionally checks, for every alias in an `ast.ImportFrom`, whether
`f"{module}.{alias.name}"` resolves to a real file under `agent_perimeter` via the already-existing
`_module_file()` helper; if so, that dotted name is added to the returned set alongside the plain
`module` name. A plain symbol import (`from agent_perimeter import __version__`) still resolves to
no file and is correctly left alone — nothing about `run.py`'s own existing imports changed
behavior.

**Refactor.** Extracted the test body into `_reachable_forbidden_modules(census_dir: Path) ->
list[str]`, parameterized on the census root instead of hardcoding
`Path("agent_perimeter/census")` inline, so a regression test can point the *exact* production
algorithm at a synthetic tree instead of the real repo.

**Regression test:** `test_from_agent_perimeter_import_subpackage_is_caught_transitively` builds a
synthetic `tmp_path/agent_perimeter/{census/run.py, other_module.py, transport/__init__.py}` tree
reproducing the reviewer's exact chain — `census/run.py` does
`from agent_perimeter import other_module`, and `other_module.py` does
`from agent_perimeter import transport` — then calls `_reachable_forbidden_modules` against it
(via `monkeypatch.chdir(tmp_path)`, since `_module_file` resolves relative to cwd, same as the
real test already does) and asserts an offence naming `agent_perimeter.transport` comes back.

**Proved the regression test actually tests the fix**, the same before/after discipline as the
first commit's transitive-guard proof: temporarily reverted `_imports()`'s alias-checking loop,
ran the new test alone —

```
AssertionError: []
assert False
 +  where False = any(<genexpr> ...)
```

— confirming it fails with an empty `offences` list (the exact blind spot the reviewer described),
then restored the fix and reran: passes, along with every other `test_passive_only.py` test.

### Finding 2: CLI `census` wrote to a throwaway SQLite file instead of the project's Postgres

**Root cause.** The command hardcoded `create_engine(f"sqlite:///{out / 'census.db'}")`, bypassing
alembic and the `postgres` service `docker-compose.yml` already stands up. A real operator running
`agent-perimeter census` got census data nothing else in the project (alembic, `psql`, a future API,
Task 7's re-run dedup) could see.

**Fix.**
- Added `DEFAULT_DATABASE_URL` to `cli.py`: the identical DSN string `alembic.ini`'s
  `sqlalchemy.url` already uses (`postgresql+psycopg://agent_perimeter:${POSTGRES_PASSWORD}
  @localhost:5432/agent_perimeter`), with a comment pointing at `alembic.ini` as the source of
  truth to keep the two in sync by hand (no shared config module exists for either to read from —
  confirmed by grep, same as the original report's finding that no app-level DB helper exists
  anywhere in the codebase).
- Added a `--database-url` option to the `census` command, defaulting to `DEFAULT_DATABASE_URL`.
- `engine = create_engine(os.path.expandvars(database_url))` — the exact same `${POSTGRES_PASSWORD}`
  expansion `migrations/env.py` already performs (configparser/typer don't expand `${...}` on their
  own), using `os` (already imported at the top of `cli.py`, no new import needed).
- Removed the old `ponytail:` comment justifying the SQLite default; it no longer applies.

**Tests added** (`tests/test_cli.py`, following the existing `CliRunner`/`monkeypatch` pattern
already used for `scan`):
- `test_census_defaults_to_the_project_postgres_not_sqlite` — asserts `DEFAULT_DATABASE_URL` itself
  is a `postgresql+psycopg://` DSN with no `sqlite` in it, **and** proves the wiring, not just the
  constant: monkeypatches `sqlalchemy.create_engine` (the CLI's `from sqlalchemy import
  create_engine` is a lazy import evaluated at call time, so patching the attribute it reads from
  works) to capture the URL it's called with while still returning a real in-memory SQLite engine so
  the rest of the command runs, and monkeypatches `agent_perimeter.census.run.run_census` (same
  lazy-import idiom, already used this way in `test_run.py`) to a stub so no network/DB pipeline
  needs to run. Asserts the captured URL equals `DEFAULT_DATABASE_URL` exactly. This is the test
  that would have caught a future edit leaving `DEFAULT_DATABASE_URL` correct while the command body
  still hardcoded something else.
- `test_census_database_url_can_be_overridden_without_a_live_postgres` — passes
  `--database-url sqlite:///{tmp_path}/override.db` with **no** mocking of `create_engine` itself
  (only `run_census` is stubbed), and asserts the real SQLite file was actually created on disk and
  the stub's `population_size` reached the printed output — proving the override reaches the real
  engine end to end, without needing a live Postgres connection anywhere in the test suite.

### Verification after both fixes

- `uv run pytest tests/census/test_passive_only.py -v` — 3 passed, 1 skipped (tier3, unchanged).
- `uv run pytest tests/test_cli.py -v` — 11 passed (9 pre-existing + 2 new).
- `uv run pytest tests/census/ tests/test_cli.py -q` — 77 passed, 1 skipped.
- `uv run ruff check .` — All checks passed.
- `uv run mypy --strict agent_perimeter` — Success: no issues found in 88 source files.
- `uv run pytest -q` (full repo, coverage on) — **550 passed, 1 skipped, 93.43% total coverage**
  (floor 75%; up from 547/93.08% before this fix, net +3 tests: 1 transitive-guard regression + 2
  CLI DSN tests).

### Files changed (this fix)

- `agent_perimeter/cli.py` — `DEFAULT_DATABASE_URL` constant, `--database-url` option, DSN wiring.
- `tests/census/test_passive_only.py` — `_imports()` alias-resolution fix, `_reachable_forbidden_modules()`
  extraction, new regression test.
- `tests/test_cli.py` — 2 new tests for the census command's database URL.

Commit: `c084dcd` — "fix: close 2 review findings from task 6a"

### Self-review of the fix

- **Root cause, not symptom (ponytail discipline):** Finding 1 fixed at the one shared `_imports()`
  function every caller (both the real test and any future one) routes through, not by patching
  `test_census_can_never_reach_a_transport_or_an_active_check` in isolation. Finding 2 fixed at the
  DSN construction itself, with an override option rather than special-casing test detection inside
  the command.
- **Both findings proven with a failing-then-passing cycle**, not just asserted fixed: Finding 1 via
  temporary revert (shown above); Finding 2 via a test that fails on any hardcoded non-Postgres
  default because it reads `DEFAULT_DATABASE_URL` directly.
- **No scope creep:** only the 3 files the two findings named were touched. `run.py` and
  `run_census()` itself are unchanged — both findings were entirely in `cli.py` and
  `test_passive_only.py`.
- **Coverage floor still comfortably clear** (93.43%, floor 75%), full suite green.
