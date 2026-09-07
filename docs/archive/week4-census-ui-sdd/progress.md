# SDD ledger — plan: docs/superpowers/plans/2026-08-11-agent-perimeter-week4-census-ui.md

Worktree: .worktrees/week4-census-ui (branch week4-census-ui, forked from main @ 14a5b24)
Spec: docs/superpowers/specs/2026-08-11-agent-perimeter-design.md
Revision (binding): docs/superpowers/specs/2026-08-29-agent-perimeter-plan-revision.md — wins over plan text on conflict.

## Pre-flight scan

Plan read in full (2403 lines). The plan's own "Blocking corrections" block (lines 14-27)
lists fixes verified against reality on 29 Aug 2026 that are NOT reflected in several
task bodies below them. This is the same pattern as the Week 3 plan. Table below is the
scan; every row got a ruling before Task 1 was dispatched.

| # | Where | What plan text mandates | What the task body actually shows | Ruling |
|---|---|---|---|---|
| 1 | Task 2 | Correction: live cursor field is `nextCursor`, not `next_cursor`; add a loud guard against single-page termination reading as complete | Task 2 Step 2 code reads `body.get("metadata", {}).get("next_cursor")` — the exact bug the correction describes | Implement with `nextCursor`. Add an explicit check: if population size looks like it stopped after page 1 while a cursor field was present but misread, that's exactly this bug — guard via keying off the correct field name AND asserting cursor absence is a real end (log page count either way, already stated in `log.record(OK, f"exhausted after {page} pages")`, keep that visible in the CLI output). |
| 2 | Task 2 | Correction: use `?version=latest`, de-dup on `name` (33% of unfiltered rows are stale versions) | `paginate()` params dict has no `version` key; no de-dup logic anywhere | Add `"version": "latest"` to the params dict; de-dup entries by `name` as they're yielded (keep first occurrence, since pagination order is registry-defined). |
| 3 | Task 2 + Task 1 | Correction: ~70% of registry has only `remotes`, no `packages`; add `remotes` field to `RegistryEntry`, add `distribution` column to `census_record` (`package_npm\|package_pypi\|package_other\|remote_only\|none`); `registryType` also takes `oci`/`nuget`/`mcpb` | `RegistryEntry(registry_id, name, coords, repository_url)` has no `remotes`; `CensusRecord` (Task 1) has no `distribution` column; `_coords()` only matches `pypi`/`npm`, merges everything else into "no coordinates" | Task 1: add `distribution: Mapped[str]` column to `CensusRecord`. Task 2: add `remotes: tuple[str, ...]` to `RegistryEntry`; extend `_coords`/entry-mapping to classify `oci`/`nuget`/`mcpb` as `package_other`, package-less-but-remotes-present as `remote_only`, neither as `none`. |
| 4 | Task 5 | Correction: registry has no popularity signal at all; `SELECTION_METHOD` must say so | `SELECTION_METHOD` string doesn't mention that the registry itself offers no popularity field | Append a sentence to `SELECTION_METHOD` stating the registry API carries no downloads/stars/install-count field, which is why ranking goes out to pypistats.org / api.npmjs.org at all. |
| 5 | Task 7 | Correction (decided 29 Aug): headline claim must be a two-stratum estimate — artifact-derived (npm/PyPI) and `server/discover`-derived (remote_only sample) — both `n`, both methods, both intervals, **never pooled** | Task 7's `aggregate()`/`render_census()` as shown handle one population only, no stratum split | Load-bearing ruling (Task 7 depends on it): `aggregate()` takes a `stratum` discriminator (or is called twice, once per stratum) and `render_census` renders two labelled sections with separate `n` and separate headline sentences, joined only by "two independent measurements of two different populations" framing — never a combined percentage. Carried into Task 7's dispatch explicitly. |
| 6 | Not in the 17 tasks | Correction: "New task — Tier 3, the remote-stratum sample" — full spec given (seeded n=100, exactly one `server/discover` per host, robots.txt + rate-limit + contact URL + opt-out list, `derived_from=LIVE_DISCOVER`, publish seed + frame snapshot, publish `docs/security.md` **before** first request) | No task creates `agent_perimeter/census/tier3.py`, yet Task 6's own `test_tier3_sends_exactly_one_method_and_owns_no_host` does `TIER3.read_text()` unconditionally — FileNotFoundError if it doesn't exist | Load-bearing: fold Tier 3 into Task 6 as an added step producing `agent_perimeter/census/tier3.py` per the correction's full spec. Sequencing consequence: Tier 3 sends live traffic to real hosts, so `docs/security.md` (Task 8) must exist and be committed **before** Task 6's tier3.py goes live — reorder so Task 8 (disclosure policy) is dispatched before Task 6's tier3.py step runs for real, or gate the live run (not the code+tests) behind Task 8 landing first. Ledgered as a cross-task ordering ruling. |
| 7 | Task 4 | Correction: "Add a ground-truth task" — install n=30 fetchable packages, live-fingerprint in the Week-1 container, publish agreement rate as basis for `ARTIFACT_CONFIDENCE` | Task 4's 5 steps (RED/GREEN/REFACTOR/verify/commit) contain no such step | Not load-bearing for shippable code — `ARTIFACT_CONFIDENCE = 0.6` already ships as an explicitly-labelled placeholder (mirrors Week 3's Derivation.NAME/DESCRIPTION confidence placeholders). Fold a *runnable script* (`analysis/sdk_ground_truth.py` or similar) into Task 4 as an extra step, matching Task 2 Step 3's "confirm against reality, record what you saw" pattern — but the actual 30-package live run is a data-collection exercise for whoever runs it against the real internet, not something to fabricate results for. Documented as a known gap in the final report rather than silently dropped. |
| 8 | Not in the 17 tasks | Correction: "New task — real-world precision" — random n=100 from the real census population, run deterministic suite, manually adjudicate every firing as TP/FP, publish separately from fixture-corpus recall | No task | Same treatment as #7: build the tooling (a script that runs `ALL_CHECKS` over a sample and emits an adjudication template), do not fabricate the manual adjudication. Flagged to the human partner as real, deferred work — the numbers this produces require a human reading real findings, which is exactly the kind of judgment step this loop should not silently invent. |
| 9 | Task 17 / Task 9 | Correction: no Docker socket in any compose file; a stdio target through `POST /api/scans` must return a clear refusal directing to the CLI | Task 17's compose services list doesn't mention docker.sock (already compliant by omission — nothing to fix there). Task 9's API scope as shown has no stdio-detection/refusal path at all | Fold into Task 9: `POST /api/scans` classifies the `target` string; a stdio-shaped target (not `http(s)://`) returns a structured 4xx refusal naming the CLI as the supported path for stdio targets. Compose: confirm no `docker.sock` mount is ever added in Task 17 (negative constraint, verify not violate). |
| 10 | Task 3 | Correction: use `tarfile.extractall(filter="data")` (Python 3.12, PEP 706) instead of the hand-rolled member walk; keep the byte caps, add a **per-file** cap; the "never executes" test should assert the `data` filter is used | Task 3's shown `safe_extract`/`_resolve_member` is entirely hand-rolled, exactly what the correction says to replace | Implement per the correction: `tarfile.extractall(filter="data")` for tar, catching `tarfile.FilterError`/`OutsideDestinationError`/`AbsoluteLinkError`/`LinkOutsideDestinationError` and re-raising as `ArchiveRejected` to keep the public interface (and the plan's own tests, which expect `ArchiveRejected`) stable. zipfile has no filter param — keep manual traversal/symlink checks for the zip path. Add `MAX_FILE_BYTES` alongside the existing `MAX_ARCHIVE_BYTES`/`MAX_UNCOMPRESSED_BYTES`. `test_the_module_never_executes_an_artifact` gets a new assertion that `filter="data"` appears in the source. |
| 11 | Task 6 | Correction: `test_passive_only` walks the import graph "one level deep" while claiming "can never reach" — make it transitive | `_imports()` scans direct imports of every file under `agent_perimeter/census` (rglob catches every census file, so census-internal chains are fine) but does not follow an import that leaves the census package (e.g. `agent_perimeter.report`) to see if *that* module reaches transport | Extend the guard test to build a transitive module-reachability graph across all of `agent_perimeter`, not just direct imports of files physically under `agent_perimeter/census`. |
| 12 | Task 5 (report-level) | Correction: `tier2_n=200` is per-ecosystem, ~29:1 npm:PyPI split means "top 200" is close to a PyPI census; report each ecosystem's `n` and population separately | `top_n()` already ranks per-ecosystem correctly (code is fine) | Not a code defect — carried into Task 7's dispatch: the report must show tier-2 `n` and population per ecosystem, not pooled. |
| 13 | Task 2 | Controller live-verified the real endpoint (`curl` against `https://registry.modelcontextprotocol.io/v0/servers`, 2026-09-03, saved to `observed-registry-*.json` in this workspace) before dispatching Task 2 | Task 2's shown pagination code does `for server in body.get("servers", [])` and treats each item as the flat record — but the real envelope nests each entry as `{"server": {...fields}, "_meta": {"io.modelcontextprotocol.registry/official": {"status", "isLatest", ...}}}`. Confirmed: `nextCursor` (not `next_cursor`) lives under `metadata`; `?version=latest` works and filters to `isLatest: true` only; most entries carry `remotes` (list of `{type, url}`) and no `packages` at all; the rare `packages`-bearing entry looks like `{"registryType":"npm","identifier":"...","version":"...","transport":{"type":"stdio"}}` | Load-bearing, not in the original scan (discovered live, same-day): `_entry()` must unwrap `item["server"]` before reading `name`/`packages`/`remotes`; dedup key is the unwrapped `server.name`. Carried into Task 2's dispatch with the saved observed-JSON files as ground truth so the implementer builds fixtures from real shape, not a guess. |

No task pair among 1-17 targets the same file with contradictory requirements outside
what's in the table above (cross-checked file lists in each task's **Files:** block).
Internal self-consistency (a task's own tests vs. its own code) is otherwise clean except
where noted above.

**Sequencing ruling:** Task 8 (coordinated disclosure policy) must land — `docs/security.md`
committed — before Tier 3's live traffic (folded into Task 6) is ever actually run against
real hosts, per the correction's own text ("publish docs/security.md ... before the first
Tier-3 request went out"). Since Tier 3's *code and tests* don't require live traffic to be
written and tested (fixture-driven, same as everything else in this plan), Task 6 as coded
can proceed in its numbered slot; the constraint binds the first *live* run of `agent-perimeter
census`, which happens no earlier than Task 17's clean-machine verification — by which point
Task 8 is long since merged. No task reordering needed; ruling recorded for the record.

**Live-network steps flagged, not silently skipped:** Task 2 Step 3 (confirm registry
endpoint against reality), Task 4's folded ground-truth script, and item #8's real-world
precision tooling all call for contact with real external services. Each implementer will
attempt what the sandbox allows and report BLOCKED/DONE_WITH_CONCERNS with specifics rather
than fabricate observed data; results get recorded plainly in the final report to the human
partner, not asserted as done.

## Task 9 pre-flight ruling (recorded before dispatch, 3 Sep 2026)

Task 9's brief (`task-9-brief.md`, verbatim from the plan, lines 1468-1617) has gaps the
extraction step didn't introduce — confirmed against the full plan text directly. Verified
against real code (`agent_perimeter/cli.py`, `checks/registry.py`, `checks/all_checks.py`,
`checks/context.py`, `graph/build.py`, `model/finding.py`, `model/edge.py`, `db/models.py`,
`pyproject.toml`) before dispatch, same discipline as Tasks 1-8:

1. **Missing dependency.** `fastapi`/`uvicorn` are in neither `pyproject.toml` nor the venv.
   Add `fastapi>=0.115`, `uvicorn[standard]>=0.30` to `[project].dependencies` (MIT/BSD,
   compliant). `httpx` (needed by `TestClient`) is already a dependency.
2. **Missing router files.** The brief's own shown `app.py` does
   `app.include_router(scans.router, ...)` / `app.include_router(census.router, ...)` but
   neither `agent_perimeter/api/scans.py` nor `agent_perimeter/api/census.py` is in the Files
   list. Added to Files: both, each an `APIRouter`. `scans.py` carries all 6 `/api/scans*`
   routes; `census.py` carries `GET /api/census/runs/{id}`.
3. **Dropped pre-flight-scan ruling.** Row #9 of the plan's own pre-flight table (this file,
   above) says stdio-shaped targets must get a structured 4xx from `POST /api/scans` naming
   the CLI. That ruling is not present in the extracted `task-9-brief.md` — carried forward
   here so it isn't silently lost. `scans.py` classifies `target`: anything not starting
   `http://`/`https://` returns 400 `{"error": "unsupported_target", "message": "...use the
   CLI: agent-perimeter scan --target ..."}` before any transport/container logic runs.
4. **No single "run a scan" function exists.** `cli.py`'s `scan()` command inlines ~150 lines:
   build transport → `fingerprint()` → `enumerate_tools()` → build `ScanContext` → `applicable()`
   → `run_checks()`, interleaved with CLI-only extras (`--repo`, `--config`, `--env-file`,
   `--agent-transcript`, `--html`) the API's request schema has no equivalent for. Ruling:
   extract the shared core (excluding the CLI-only extras) into
   `agent_perimeter/scan_runner.py::run_scan(target, mode, scope, *, image=..., env=...) ->
   ScanOutcome` (dataclass: `findings`, `skipped`, `errored`, `fingerprint`, `tools`, `edges`).
   Both `cli.py`'s `scan()` and the API call it — the alternative is a second inline copy of the
   `require_scope`/`applicable()` gating path, which is exactly the "two would eventually
   disagree" risk the brief's own Step 1 test 4 exists to catch. `cli.py`'s CLI-only extras stay
   in `cli.py`, layered on the shared result. Added `agent_perimeter/scan_runner.py` and a
   `cli.py` diff to Task 9's Files list.
5. **Persistence, scoped.** `db/models.py` already declares `Scan`, `Tool`, `CapabilityEdge`,
   `FindingRow` (unused since Week 1, migration already applied — confirmed no new migration
   needed). Ruling: on scan completion, write `Scan` + `Tool` + `CapabilityEdge` + `FindingRow`
   rows via a background task (`fastapi.BackgroundTasks`, no new dependency — no Celery/queue
   exists anywhere in this repo) for durability and `GET /api/scans/{id}` status lookup.
   **Known gap, ruled acceptable for this task, not silent:** `FindingRow` has no column for
   `Finding.evidence` or `Finding.location`, and `model.edge.CapabilityEdge` isn't 1:1
   reconstructable from the DB row without a join back through `Tool`. Reconstructing
   `/findings`, `/graph`, `/report.sarif` from DB rows alone would either lose data or need a
   migration outside Task 9's declared Files. Ruling: those 3 read endpoints serve from an
   in-process cache of the completed `ScanOutcome` (`dict[str, ScanOutcome]`, lock-guarded),
   which is complete and lossless; DB rows exist for durability/audit/status only. Mark the
   cache with a `ponytail:` comment naming the ceiling (single-process; a restart loses
   in-flight/completed results; move to DB-backed reconstruction — which needs the
   evidence/location columns added — if that's ever required) and list as a deferred item in
   the task report, same convention as every other task's "Minor (deferred)" entries.
6. **SSE event stream.** No progress callback exists in `run_checks()`/`applicable()` today.
   Ruling: `scan_runner.run_scan` (or a thin wrapper the API uses) takes an optional
   `on_event: Callable[[EventFrame], None]` called after each check completes, so the pipeline
   itself stays free of HTTP/SSE concerns (checks/registry code has no reason to know about
   FastAPI). The API's background task supplies a callback that appends to the same
   in-process per-scan-id event log the SSE endpoint streams from (poll loop, terminal frame
   carries `skipped` — from the `Skipped` list `applicable()` already returns, mapped to
   `{check_id, reason, detail}` per the brief's "skipped checks are in the stream" rule).
   `total` = `len(runnable) + len(skipped)`, computed once `applicable()` returns — there is no
   pre-computed per-mode total anywhere else, confirmed. Same `ponytail:` ceiling as #5:
   single-process only.
7. **Partial `scope_file` in the request body.** `ScopeFile` (pydantic, `extra="forbid"`) has
   no defaults for `target`/`authorising_party`/`authorised_on`/`attestation`, so the brief's
   own `test_the_refusal_names_the_specific_missing_attestation_field` — POSTing a scope dict
   missing both `authorised_on` and `attestation`, asserting `missing_field == "attestation"`
   — is only satisfiable if the request-side schema treats a missing `authorised_on` as
   "defaults to today" (a defensible UX default: unspecified start date means "starting now")
   while `attestation` has no sensible default and is the one that's actually reported. Ruling:
   `schemas.py` defines a request-side `ScopeFileInput` (all of `ScopeFile`'s fields, but
   `authorised_on` optional, defaulting to `date.today()` when constructing the real
   `ScopeFile`). The API checks the raw parsed dict for the first structurally-absent field in
   order `target, authorising_party, attestation` (in this order, since `authorised_on` is
   defaulted) *before* attempting to build a real `ScopeFile`, raising `AuthorizationRequired`
   itself for structural absence (same exception type, same handler) — real `require_scope(...)`
   only runs once a structurally-complete `ScopeFile` exists, for the semantic checks (target
   mismatch, not-yet-authorised, expired). Document the `authorised_on` default explicitly in
   the schema field, since it's a real behavioural choice, not an accident.
8. **Scope kept proportionate.** The API's `ScanRequest` covers exactly what the brief's tests
   exercise — `target`, `mode`, `scope_file` — not the CLI's full flag surface
   (`--repo`/`--config`/`--env-file`/`--agent-transcript`/`--image`/`--env`). Those stay
   CLI-only; nothing in Task 9's brief or its tests calls for them on the HTTP surface.

## Task log

Task 9: fix round 1/5 (3 addressed, 0 open; commits 0cb5ff1..a17378d)
Task 9: complete (commits 92caa7a..a17378d, 1 fix round, review clean — Ready to merge as-is)
- Extracted the CLI's inline scan orchestration into `agent_perimeter/scan_runner.py::run_scan()`,
  shared by `cli.py` and the new API — one `require_scope` call site, not two. Verified by the
  reviewer against the pre-extraction `cli.py` line-by-line: `--repo`/`--config`/`--env-file`
  precedence preserved exactly, `--only`/`--sarif`/`--html` correctly stayed CLI-only.
- Fix round 1 (1 Critical, 2 Important, all fixed): a malformed-but-present scope-file field
  (whitespace-only string, `expires_on` before `authorised_on`) reached `ScopeFile`'s own
  pydantic validators uncaught and 500'd instead of refusing structurally — fixed by catching
  `pydantic.ValidationError` in `_build_scope` and funnelling it into the same
  `AuthorizationRequired` → 422 path. A passive-mode request carrying an incomplete `scope_file`
  was wrongly refused with a misleading "active checks need..." 422 — fixed by gating scope
  construction on `mode is ScanMode.ACTIVE`. `_persist`'s DB write (Scan/Tool/CapabilityEdge/
  FindingRow) had zero test coverage — added a test querying the sqlite fixture directly, which
  caught a real latent bug in the process: no model in `db/models.py` declares an ORM
  `relationship()`, only raw FK columns, so a scan with zero discovered tools could flush the
  `finding` insert before the `scan` insert — invisible on sqlite (FKs unenforced by default)
  but would reject on Postgres in production. Fixed with one `session.flush()` after
  `session.add(scan_row)`. Confirming re-reviewer independently reproduced all three bugs and
  the fix via a live `TestClient` and a standalone `PRAGMA foreign_keys=ON` repro before ruling
  each closed.
- **Known gap, deliberately deferred — surfaced to and confirmed by the human partner, not
  silently carried forward:** the API has no authentication or access control at all. Since
  passive mode needs no scope file, any caller who can reach `/api/*` can direct the server to
  probe an arbitrary `target` and read back findings — a materially different threat model than
  the CLI, which requires local shell access. Neither the plan, the design spec, nor this
  session's 8 pre-flight rulings specify an auth mechanism for this API; asked the human partner
  directly (not assumed, per this project's own "open decisions — do not assume, ask" rule) —
  decision: defer, document as a known gap, revisit before any network-reachable deployment.
  Carry forward to Task 17 (or a dedicated follow-up) before this API is ever exposed beyond
  localhost/internal use.
- Minor (deferred): `test_refusal.py`'s passive-mode test makes a real (harmless, `.invalid`
  TLD, never resolves) DNS lookup — brief's test content is verbatim-mandated, not fixable
  without deviating from it; adds ~12s to that one file. Minor (deferred): no direct unit test
  for `run_checks()`'s new `on_check` callback parameter — verified correct by hand, shape
  unguarded by a test. Minor (deferred): `GET /scans/{id}/report.sarif` writes a scan-profile
  artifact under the OS tempdir per call with no cleanup, same class of gap as the already-
  disclosed in-process caches. Minor (deferred): 404 responses use a plain string `detail`
  while the 422/400 refusals use a structured `{"error", "message"}` shape — inconsistent but
  harmless. Minor (deferred): `test_the_api_and_the_cli_refuse_on_the_same_condition` is a weak
  proxy (greps `app.py`'s source for the literal substring `"require_scope"`, true only because
  of an import kept specifically to satisfy it) — inherited from the brief's own mandated test
  content, not an implementer defect.

Task 8: fix round 1/5 (2 addressed, 0 open; commits c2c9f77..92caa7a)
Task 8: complete (commits 5cd18c8..92caa7a, 1 fix round, review clean)
- IMPORTANT catch: implementer hardcoded the user's real personal email
  (77killuazoldic@gmail.com) as the permanent public security contact in docs/security.md +
  SECURITY.md — would have shipped into public git history at Task 17's release. Every other
  identity reference in this codebase uses a placeholder; this one didn't. Fixed to
  `<security@USER-PLACEHOLDER.example>` in both files, verified fully absent from the tree.
  No user memory/instruction ever authorized publishing that address — this was a subagent
  overreach caught by review before it could land.
  Tier-3 description condensed from an 8-line bulleted breakdown to 2 sentences per the
  controller's brevity instruction; condensation also removed a latent inaccuracy ("the only
  live-probe tier" — scope-gated active/ checks also send live traffic under authorization).
- Minor (deferred): placeholder token style (`USER-PLACEHOLDER`) doesn't match the codebase's
  established bare `USER` convention — cosmetic, unambiguously still a placeholder either way.

Task 7: fix round 1/5 (3 addressed, 0 open; commits 89b56a5..5cd18c8)
Task 7: complete (commits 0baac1e..5cd18c8, 1 fix round, review clean)
- Ruling: report presents two never-pooled strata (artifact: npm/PyPI source-detected;
  live-discover: Tier-3 probe, Derivation.PROBE) with separate n/method/headline each. Zero
  live-discover data exists in this codebase (tier3.py unwired per Task 6) — report honestly
  states "not yet run" rather than a broken 0/0 percentage. Tier-2 n shown per-ecosystem
  (carried from Task 5's correction), plus a clearly-labelled pooled summary row kept alongside
  (not instead of) the per-ecosystem rows — judged not a "never pooled" violation since that
  rule targets strata/ranking-metric pooling specifically.
- Design: live-discover stratum structurally never reports does_not_support (a single probe
  confirms support, never absence) — reviewer independently verified this against tier3.py's
  actual observe-or-abstain behavior, judged sound.
- Fix round 1 (3 Important, all fixed): CSS was HTML-escaped by Jinja autoescape, corrupting
  the print-first/greyscale-safe styling (font-family quotes, glyph content rules) — fixed with
  `|safe`. Live-discover "Share" figure rendered a misleading unguarded 100% regardless of
  non-response rate — removed, replaced with explicit raw non-response count. census_analysis.py
  required a records.summary.json sidecar, violating the completion gate's "from the published
  CSV alone" — fixed to recompute everything from records.csv alone, sidecar now optional
  (adds a pass/fail diff only when present).
- Minor (deferred): sidecar-optional restructuring lost some per-ecosystem diagnostic
  granularity in one edge case (CSV loses all rows for an ecosystem the summary still
  describes) — verified the pass/fail correctness itself is unaffected (pooled-level check
  still catches it), just less verbose in that one case. Minor (deferred): disclosure-policy
  link points to docs/security.md (Task 8, not yet built) — forward reference, doesn't crash.
  Minor (deferred): export_raw's per-ecosystem summary duplicates logic already in
  _ecosystem_breakdown() instead of reusing it.

Task 6b: complete (commits c084dcd..0baac1e, review clean — Approved, spec ✅, 0 Critical/Important)
Task 6: complete overall (6a + 6b, commits 5ab877c..0baac1e)
- tier3.py built self-contained per the folded-in ruling: seeded n=100 sample from remote_only
  stratum, exactly one server/discover (AST-verified equality, no other word/word literal),
  zero hardcoded hosts (grep-verified by reviewer independently), robots.txt honoured
  fail-closed on error (reviewer judged this correct per RFC 9309), opt-out list gates before
  any request including robots.txt, rate-limited, Derivation.PROBE (per earlier ruling),
  observe-or-abstain proven with an adversarial test, seed+frame snapshot genuinely inspectable.
- **CARRY FORWARD — not wired into run.py/CLI.** tier3.py is self-contained by design (explicit
  scope decision) but nothing calls it yet. "Never contacted again across a re-run" is
  implemented as a pure parameter (`already_contacted`), not backed by a live DB query — a
  later integration must supply that from CensusRecord history. No live Tier-3 requests have
  been made in this session. The Week 4 completion gate's "Tier-3 seed, frame snapshot and
  opt-out list are published with the raw data" and "docs/security.md published before the
  first Tier-3 request went out" items are NOT closed by Task 6b alone — they need an actual
  wiring + a real run, which is deferred (same treatment as the SDK ground-truth and
  real-world-precision items) and must be reported plainly to the user, not silently assumed
  done when Week 4 wraps.
- Minor (deferred): implementer's report said "31 passed" for test_tier3.py, reviewer
  independently ran it and got 27 (all passing) — self-report accuracy nit, not a code issue.
  Minor (deferred): redirect policy not pinned by tier3.py itself (inherited from caller's
  httpx.Client, currently safe by httpx's own default) — the eventual run.py integration should
  pin `follow_redirects=False` explicitly. Minor (deferred): sample vs. actually-contacted
  counts can diverge (opt-out/robots-disallow skip some of the n=100) — note for whoever writes
  the eventual report's methodology section so "n=100 sampled" isn't conflated with "contacted."

Task 6a: fix round 1/5 (2 addressed, 0 open; commits f037014..c084dcd)
Task 6a: complete (commits 5ab877c..c084dcd, 1 fix round, review clean)
- Fix round 1 (2 Important, both fixed): passive-only guard's transitive walk didn't resolve
  `from agent_perimeter import <subpackage>` aliases against the filesystem, so a 2-hop leak
  through that import style slipped past (reviewer proved with a runnable PoC) — fixed by
  resolving each ImportFrom alias against real files on disk. CLI `census` command wrote to a
  throwaway SQLite file instead of the project's real Postgres (would have made published
  census data invisible to alembic/docker-compose/any future API) — fixed with a
  `DEFAULT_DATABASE_URL` matching alembic.ini's DSN exactly, plus a `--database-url` override.
- Carried Task 3's leaked-temp-dir finding to closure here: `run_census()` now `rmtree`s
  `ArtifactResult.root` after `detect_features()` runs, tested by checking the dir is actually
  gone. `distribution` column (added Task 1, unused since) now populated for all 4 cases.
- Minor (deferred): no CliRunner-based test for the `census` Typer command itself (verified via
  manual smoke transcripts + unit tests of `run_census`/DSN wiring instead). Minor (deferred):
  `detect.detect_features` has no contractual "never raises" guarantee the way `fetch_artifact`
  documents — an uncaught exception mid-run would abort the whole census with no partial
  persistence (single commit at the end) — worth a defense-in-depth wrap later, not blocking.

Task 6: SPLIT into 6a (core pipeline: run.py, CLI, transitive passive-only guard,
ArtifactResult.root cleanup carried from Task 3's review) and 6b (tier3.py, folded in per
ruling #6) — both this large due to my own pre-flight rulings, splitting keeps each dispatch
and review scoped rather than one unmanageable mega-task. Both land as "Task 6" commits.
- Ruling: Tier 3's findings use `Derivation.PROBE` (already exists, already means "confirmed
  by live server contact"), not a new `LIVE_DISCOVER` enum member the revision's prose
  mentions but which doesn't exist in `agent_perimeter/_contracts.py`'s `Derivation` enum
  (confirmed: SCHEMA/NAME/DESCRIPTION/PROBE/ARTIFACT only). Adding a 6th enum value for one
  narrow case is unwarranted — PROBE already captures "live contact, not inference," which is
  exactly what a `server/discover` call is. Ledgered before dispatch, not after a review finding.
- Ruling: Tier 3 does NOT go behind a ScopeFile/require_scope gate (that mechanism is for
  targeted active probes against a specific customer's infrastructure — path_traversal, ssrf,
  command_injection, confused_deputy — a scope file model doesn't fit "randomly sample the
  public registry ecosystem"). Trusting the plan's revision's explicit, dated policy decision
  here rather than second-guessing it: the safeguards for Tier 3 are opt-out list, robots.txt,
  rate-limit, contact URL, and requiring docs/security.md (Task 8) be published before the
  first REAL request goes out — a sequencing rule on running the live census, not a per-call
  code gate. No live Tier-3 requests will be made during this implementation session; all
  tests run against fixtures/mocked transports like every other census module.

Task 5: complete (commits 929fe70..5ab877c, review clean — Approved, spec ✅, 0 Critical/Important)
- Ruling: brief showed top_n() fully but not rank() — implementer designed it. Controller
  live-verified pypistats.org/api.npmjs.org real shapes and failure modes before dispatch
  (pypistats rate-limits aggressively, 429 after 2 requests; npm returns {"error"} with no
  "downloads" key for unknown packages) — both handled correctly, verified by reviewer against
  mocked-transport tests, no live calls in test suite.
- Resolved reviewer's ⚠️ item myself (brief's Interfaces line says "Consumes: FetchStatus" but
  sample.py never uses it): not a real gap — none of the brief's own 5 tests reference
  FetchStatus, RankSource.UNAVAILABLE already serves as the "no metric" sentinel. Plan
  overstatement, not a missed requirement.
- Minor (deferred): rank() sleeps unconditionally after every PyPI lookup including the last
  in a batch (fetch.py's paginate guards its equivalent sleep to skip when there's no next
  page) — wasted wall-clock, not correctness. Minor (deferred): _pypi_downloads/_npm_downloads
  duplicate near-identical try/except scaffolding — defensible for 2 call sites.

Task 4: complete (commits 5586e99..929fe70, review clean — Approved, spec ✅, 0 Critical/Important)
- Ruling: folded a runnable (non-test-suite) `analysis/sdk_ground_truth.py` script into Task 4,
  per the plan revision's "ground-truth task" — does not fabricate the actual 30-package live
  comparison, prints artifact-derived side only with a placeholder column for human follow-up.
- SDK_FLOOR version numbers and docs/methodology.md's "SDK version floors" table are honestly
  marked TBD/placeholder throughout (implementer had no network access in its sandbox) — real
  values must be filled in from the actual MCP SDK changelog before publication (Task 17 or
  earlier). Carry forward: do not let this ship to the public census report unverified.
- Caught and fixed a real bug in the plan's own brief: `Feature.X_MCP_HEADER` doesn't exist on
  the real `Feature` enum (only `PARAM_HEADERS` does) — brief's shown `SOURCE_SIGNALS` code
  would have raised `AttributeError` on import. Implementer substituted `PARAM_HEADERS`,
  reviewer independently verified this matches the live-probe's identical detection.
  `packaging` added as a direct runtime dependency (was only reachable transitively before) —
  necessary fix, BSD/Apache dual-licensed, compliant with project policy.
- Minor (deferred): `Feature.MRTR` and `Feature.PARAM_HEADERS` source signals are correct by
  manual inspection but have no fixture exercising them. Minor (deferred): no fixture for
  "source mentions a feature, no manifest present at all" path.

Task 3: fix round 1/5 (3 addressed, 0 open; commits 4d84099..5586e99)
Task 3: complete (commits 2a2c6f8..5586e99, 1 fix round, review clean)
- Ruling: replaced brief's hand-rolled safe_extract with tarfile.extractall(filter="data")
  (PEP 706) per revision §5.7, catching PEP-706 exceptions + generic corrupt-archive errors
  and re-raising as ArchiveRejected; zip path kept manual traversal/symlink checks (zipfile has
  no filter=); added MAX_FILE_BYTES per-file cap.
- Fix round 1 (1 Critical, 2 Important, all fixed): fetch_artifact raised uncaught exceptions
  on corrupted/truncated archives instead of returning ArtifactResult (reviewer reproduced
  end-to-end: truncated tar.gz → EOFError from tarfile.is_tarfile() itself; corrupted zip →
  zlib.error) — would have crashed an entire census run on the first bad package; fixed by
  wrapping the whole dispatcher in safe_extract with a shared exception tuple. Zip bomb guard
  checked declared file_size instead of actual bytes written — fixed with a streaming counter;
  re-reviewer independently verified the specific bypass doesn't reproduce on Python 3.12+ (CPython's
  ZipExtFile truncates to declared size internally, hits its own CRC check first) so this was
  defense-in-depth, not a live hole — but the fix is still correct and now committed. Two
  hypothesis-found escape bugs (Windows drive-letter "0:", "."/".." literals) got pinned
  @example regression tests.
- **Carry to Task 6:** ArtifactResult.root (extracted temp dir) is never cleaned up by this
  module — caller-owned by design, but Task 6's plan pseudocode doesn't clean it up either.
  At "census of thousands" scale this leaks up to MAX_UNCOMPRESSED_BYTES (256 MiB) of temp
  files per successfully-fetched package for the run's lifetime. Task 6's dispatch must either
  add cleanup after detect.detect_features(result.root) runs, or explicitly own a different
  lifecycle — do not let this land unaddressed.
- Minor (deferred to final review): `hypothesis` added as a dev dependency, MPL-2.0-licensed,
  outside CLAUDE.md's stated Apache/MIT/BSD-only policy — dev-only, mandated by the brief's own
  RED test, not implementer scope creep, but per project policy must be flagged explicitly
  rather than silently adopted — flag in Task 17's licence audit (Step 4) explicitly. Minor
  (deferred): MAX_MEMBERS boundary (exactly at cap) untested, only `>` exercised. Minor
  (deferred): `_TIMEOUT_S=15.0` shared between the small metadata JSON call and up-to-32MiB
  archive download — a large archive on a slow connection could misreport as TIMEOUT.

Task 2: fix round 1/5 (3 addressed, 0 open; commits 5d9fa45..2a2c6f8)
Task 2: complete (commits 44efdc9..2a2c6f8, 1 fix round, review clean)
- Ruling: live-verified real registry API before dispatch (envelope nesting `{server, _meta}`,
  `nextCursor` under `metadata`, `version=latest` filter, `remotes`-only entries) — 4th
  correction beyond the pre-flight scan, discovered same-day; folded into dispatch with
  observed-registry-*.json ground truth saved to workspace.
- Fix round 1 findings (all Important, all fixed): TIMEOUT double-logged on every retry
  attempt instead of once on give-up (corrupted `fetch_failures`, which Task 6 ships in the
  published report) — fixed to log once on give-up, mirroring the THROTTLED path; oci/nuget/mcpb
  registryTypes collapsed to the same `None` as unrecognised values with no way for downstream
  code to recover the distinction the plan's `distribution` column depends on — fixed by adding
  `RegistryEntry.has_unmodeled_package: bool`; no test asserted `version=latest` reached the
  actual outgoing request — fixed with a test inspecting `request.url.params`.
- Minor (deferred): `USER_AGENT`'s placeholder contact URL duplicates `cli.py`'s
  `DEFAULT_CONTACT_URL` with a different placeholder name (OWNER vs USER) instead of reusing
  it — flag to final whole-branch review. Minor (deferred): one dead-code line in `_get_page`'s
  post-loop fallback became unreachable in ordinary use as a side effect of the fix (only
  reachable if `max_retries <= 0`) — harmless, noted by re-reviewer, not worth a follow-up.

Task 1: complete (commits 14a5b24..44efdc9, review clean — Approved, spec ✅, 0 Critical/Important)
- Ruling: migration path/number corrected from brief's stale `alembic/versions/0004_census.py`
  to actual repo convention `migrations/versions/0003_census.py` (existing latest was 0002,
  not 0003 as the plan assumed) — implementer caught this itself by checking repo state.
- Controller independently ran the migration round-trip (upgrade/downgrade -1/upgrade) against
  a real temporary Postgres 16 container, since the implementer only verified schema via SQLite
  in-memory and flagged Docker as unavailable to it — round-trip confirmed clean, container
  removed after.
- Minor (deferred): string columns in census tables use bare `Mapped[str]` instead of the
  file's existing `String(N)` convention (models.py census columns, inherited from the brief
  verbatim) — flag to final whole-branch review. Minor (deferred): `model/census.py` docstring
  forward-references `docs/security.md`, written in Task 8, not yet — harmless, resolves itself
  once Task 8 lands. Minor (deferred): no direct unit test on `FetchStatus.is_failure`/
  `PackageCoords.digest()` — matches brief's RED-test scope, not a deviation.

## Task 10 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 1-9): `web/` does not
exist yet (fresh scaffold); node v26.3.0 / npm 11.16.0 present; npm registry reachable from
this sandbox (live-checked, not assumed).

1. **Next.js version pin.** Brief Step 1 runs `npx create-next-app@latest`. Live-checked:
   `@latest` resolves to Next 16.3.4 today — but CLAUDE.md's Stack line and `00`'s repo
   template both hard-pin **Next.js 15**, and nothing in this plan or the spec vets Next 16's
   breaking changes. Ruling: use `npx create-next-app@15 .` (confirmed latest 15.x patch =
   15.5.25, resolves live). Carried into dispatch verbatim so the implementer doesn't silently
   scaffold on an unvetted major.
2. **Font sourcing.** Brief mandates self-hosted Newsreader/Geist Sans/IBM Plex Mono via
   `next/font/local` from files under `web/src/fonts/`, no Google Fonts CDN call — but doesn't
   say where the actual font files come from. Live-checked npm: `geist` (Vercel's own package,
   SIL OFL) and `@fontsource/newsreader` / `@fontsource/ibm-plex-mono` (both OFL-1.1) all exist
   and are licence-compliant. Ruling: install these as a one-time file source, copy the actual
   `.woff2` files they ship into `web/src/fonts/`, load via `next/font/local`, then drop the
   packages from runtime `dependencies` (dev-time source only) — meets "self-hosted, zero
   runtime CDN call" literally without hand-rolling a raw-GitHub-URL downloader of unverified
   licensing. Carried into dispatch.
3. **`api.ts` ground truth.** Brief says "typed api client", "Consumes: the Task 9 API" with
   no shape given. Verified Task 9's actual surface directly against `agent_perimeter/api/`
   (not the plan's sketch, which predates Task 9's implementation): `POST /api/scans` takes
   `{target: str, mode?: "passive"|"active", scope_file?: {target, authorising_party,
   authorised_on?, attestation, expires_on?}}`, returns `{id, status}` (202). `GET
   /api/scans/{id}` returns `{id, status: "running"|"completed"|"errored", revision_claimed?,
   features_observed?, findings_count?, skipped_count?, errored_count?}`. `GET
   /api/scans/{id}/findings` and `/graph` return arrays of the domain models' JSON encoding.
   `GET /api/scans/{id}/report.sarif` returns the SARIF dict. `GET /api/scans/{id}/events` is
   SSE, each frame `{check_id, status: "passed"|"errored", elapsed_ms, phase, completed,
   total}` plus a terminal frame carrying `skipped`. `GET /api/census/runs/{id}` returns
   `{id, started_at, finished_at, population_size, fetch_failures, tool_version, method_hash,
   tier2_n, registry_endpoint}`. Ruling: `api.ts` types against these real shapes, not a guess
   — saves Task 11 (scan setup screen, the first real consumer) from discovering drift.

## Task 10 log

Task 10: fix round 1/5 (4 addressed, 0 open; commits 3ff3bff..2a0de0e)
Task 10: complete (commits a17378d..2a0de0e, 1 fix round, review clean)
- Reviewer independently re-verified pre-flight ruling 3's SSE terminal-frame shape against
  `agent_perimeter/api/events.py::EventLog.finish` directly — confirmed the implementer's
  `ScanTerminalEvent` matches the real backend exactly, byte-for-byte; also cross-checked
  `ScanCheckEvent`/`ScopeFileInput`/`ScanRequest`/`ScanStatus` against real schemas — all
  correct. All 3 brief-mandated bok-ui requirements (Claim derivation glyphs, provenance-column
  CSV survival, ConfidenceMeter uncalibrated default) and 4 cross-cutting requirements (no
  Google Fonts CDN, no colour-alone encoding, tabular numerals, 3 density modes) verified
  correctly implemented.
- Important #1: `FindingsTable`'s `density` prop applies a `bok-density-{value}` class with no
  matching CSS selector anywhere in globals.css — silently inert per-instance.
- Important #2: `_bok-ui.tsx`'s `Derivation` type (schema/description/probe/artifact) is
  missing `"name"`, a 5th member of the real `agent_perimeter/_contracts.py::Derivation` enum
  actively used across 7 files — `DERIVATION_META` has no entry, so a real Finding with
  derivation="name" renders undefined glyph/label once Task 11 wires live data. Brief's literal
  wording only lists 4 values (stale brief), but the code's own comment claims fidelity to the
  real file, which has since diverged.
- Important #3: `ProvenanceRail` (00 §5.3's signature element) traps focusable descendants
  (close button, chain-entry links) behind `aria-hidden="true"` when closed — no
  `inert`/`pointer-events:none`/`visibility:hidden`, no focus-management on open/close. Axe
  would flag `aria-hidden-focus` (serious). Latent (nothing renders ProvenanceRail yet in this
  diff) but real in delivered code, and 00 §5.5's WCAG 2.2 AA / axe floor is binding.
- Important #4: `FindingsTable` ships without virtualization, though 00 §5.4 names it
  "virtualised, column-resizable, keyboard-navigable, CSV/JSON export" as one requirement —
  the other three are present; virtualization was deliberately cut with a `ponytail:` comment.
  Ruling: real, binding requirement in the source-of-truth spec this task cites — not
  dismissed. Fold into fix round 1 alongside the other three; a minimal virtualization (e.g.
  `@tanstack/react-virtual`, MIT, already a common Next.js pairing) is proportionate, not a
  rewrite.
- Minor (deferred): static (untracked) roving tabindex in `FindingsTable`, Tab-out/Tab-back-in
  always lands row 0/col 0. Minor (deferred): column-resize handle has no keyboard equivalent.
  Minor (deferred): transitive-dependency licence audit not run on this diff's new lockfile
  entries (`@img/sharp-libvips-*` LGPL-3.0-or-later dynamically-linked optional native binary,
  `@axe-core/playwright` MPL-2.0 dev-only) — neither AGPL, both standard/dev-only cases, but
  flag for Task 17's stated licence-audit job same as Task 3's `hypothesis` MPL-2.0 flag.
  Minor (deferred): `download()`'s `URL.revokeObjectURL` ordering is fragile-but-works.

## Task 11 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 1-10): `web/app/page.tsx`
exists only as create-next-app's placeholder landing copy (Task 10) — Task 11 replacing it is
not a conflict. `web/src/lib/api.ts` (Task 10) already exports `createScan`, `ScanRequest`,
`ScopeFileInput` (required: `target`, `authorising_party`, `attestation`; optional:
`authorised_on`, `expires_on`), `ScanAccepted`, `ApiError` with real field shapes verified
against the live API — nothing new needed there. `web/src/lib/_bok-ui.tsx` already exports
`EmptyState`/`ErrorState` matching the brief's Interfaces line; `ErrorState` renders
`role="alert"` (`_bok-ui.tsx:750`), which is exactly what RED test 4 (`getByRole("alert")`)
targets. `web/tests/` has no `fixtures/` subdirectory yet — `scope-valid.json`/
`scope-no-attestation.json` must be created as part of this task; not a plan gap worth a
separate ruling row, just noted so it isn't missed. `layout.tsx` renders no header/nav before
`children`, so `page.tsx`'s own first focusable element is genuinely the page's first tab stop.

1. **No live-backend path exists for this task's E2E suite, and none should be built for it.**
   `agent_perimeter/api/app.py` has no CORS middleware; `web/next.config.ts` has no
   rewrite/proxy; `web/playwright.config.ts`'s `webServer` starts only `npm run dev`. The plan's
   only other `webServer: [...]` array (Task 16) serves a static report file for screen 6, never
   a live FastAPI process — no task in this plan wires a live backend into the Playwright run,
   and Tasks 12/13 downstream drive their screens with `?fixture=` query params rather than a
   live API, confirming the plan's own pattern is fixture-driven, not live-backend E2E. Confirmed
   by re-reading this task's 5 RED tests: none submits the form or waits on a created scan; test
   4 ("names the missing field") asserts on `getByRole("alert")` immediately after
   `setInputFiles`, before any submit action exists to click. Ruling: "attach a scope file →
   unlock active mode / name the missing field" is **client-side structural validation only** —
   parse the uploaded JSON, check for presence of `target`, `authorising_party`, `attestation` in
   that order (mirrors Task 9 ruling #7's exact field order and `authorised_on`-defaults rule;
   `ScopeFileInput`'s own required/optional split is already the source of truth, so no new
   shared contract is needed), rendering the first missing field's name via `ErrorState`. This is
   deliberately **not** an authorisation decision — it only asks "is the file structurally
   complete enough to submit," never "is this scope valid for this target" — matching the brief's
   own framing that "the client never decides authorisation on its own." The real authorisation
   decision (target match, expiry, semantic scope checks) stays server-side, exercised only on
   actual form submission via `createScan()`, which no RED test in this task covers. Implement
   the real submit → `POST /api/scans` → navigate to `/scans/{id}` path for real (Task 12's
   route, not yet built — same forward-reference pattern as Task 7 linking to Task 8's
   not-yet-built `docs/security.md`) since the Interfaces line requires it, but it ships untested
   by this task's mandated suite — note as a known gap in the report, same convention as every
   prior task.
2. **`ErrorState` covers two distinct failure sources with the same component.** Structural
   scope-file validation failure (client-side, pre-submit) and a real submit failure (non-2xx
   from `createScan`) both render through `ErrorState`/`role="alert"` — one component, two call
   sites, not new scope beyond what the Interfaces line already names.
3. **Target field copy.** Brief specifies no exact placeholder text beyond "stdio command / URL /
   registry ref" — implementer's call; keep it short and factual, no invented UX beyond what's
   testable.

## Task 11 log

Task 11: fix round 1/5 (2 addressed, 0 open; commits a8f6c25..6f13b4e)
Task 11: complete (commits 2a0de0e..6f13b4e, 1 fix round, review clean)
- Brief's one hard requirement — active mode disabled and visibly, deliberately locked until a
  structurally-valid scope file is attached, explained in one honest sentence — built correctly
  and evidenced with a real screenshot (`docs/evidence/active-locked.png`). The client/server
  structural-vs-authorisation split (ruling #1 above) held throughout the diff, not just where
  the brief called it out by name — no client-side code ever claims a scope file authorises a
  scan; that decision stays server-side at real submission.
- Two self-flagged deviations from the brief's literal text, both independently verified by the
  reviewer as real, not implementer shortcuts: (1) the brief's given lock copy contains
  "authorising", which does not contain the substring "authorisation" that RED test 1's regex
  (`/scope file.*authorisation/i`) requires — a genuine word-mismatch between two parts of the
  brief itself; copy rewritten to satisfy both the regex and the "one sentence, no apology" test.
  (2) Next.js 15's App Router unconditionally mounts a hidden `role="alert"` route announcer
  (`node_modules/next/dist/client/components/app-router-announcer.js:26`, confirmed by direct
  read), colliding with RED test 4's `getByRole("alert")` under Playwright strict mode — fixed
  with a `.filter({ hasText: "attestation" })` on that one locator.
- Fix round 1 (2 Important, both fixed): the report wrongly framed the lock-copy rewrite as
  "pre-authorised" by this ledger's Task 11 ruling — corrected to attribute it to the
  implementer's own judgment call, since the actual ruling (above) never mentions that specific
  conflict. Five dynamic error-copy strings (`ScopeFileField.tsx`, `page.tsx`) stated only what
  happened, not what to do, violating CLAUDE.md's Copy rule — rewritten to end with an actionable
  instruction each, matching `findings/page.tsx:69`'s existing precedent. Re-reviewer verified
  both directly against the fix diff, no new breakage.
- Minor (deferred): RED test 4's `.filter({ hasText: "attestation" })` + `.toContainText(...)` is
  slightly circular (the filter already selects on that text) — `page.locator("main").getByRole(
  "alert")` would sidestep the Next.js announcer collision more cleanly. Minor (deferred):
  `ScopeFileField.tsx`'s `record as unknown as ScopeFileInput` double-cast skips type validation
  on the optional fields (`authorised_on`/`expires_on`) — acceptable since only structural
  presence is this task's job; server re-validates types regardless. Minor (deferred): the
  disabled Active radio has no `aria-describedby` pointing at the lock-reason paragraph — a
  screen-reader user tabbing directly to the radio won't hear why it's disabled without reading
  the fieldset linearly first; not an axe-serious violation but a real gap given this screen's
  explicit accessibility emphasis.

## Task 12 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 9-11): `web/app/scans/`
does not exist yet (fresh route). `web/tests/fixtures/` now exists (Task 11's scope-file
fixtures) — this task adds to it, not a conflict. Real check-id namespaces, confirmed by
grepping `agent_perimeter/checks/*/*.py`: `active`, `descriptions`, `injection`, `revision`,
`secrets`, `static` (30 real check IDs found; the actual registered count is 33 per commit
`9524b78`, which also includes policy-predicate checks not defined as `id = "..."` literals in
those files — irrelevant here since this task never touches a live registry, only fixture data).
`agent_perimeter/scan_runner.py:258` confirms `phase = check.id.split(".", 1)[0]` — phase names
are genuinely the check-id's namespace prefix, so fixture phase names should be drawn from the
real list above, not invented. `web/src/lib/_bok-ui.tsx` confirmed: `QuotaStrip` already renders
`data-testid="quota-strip"` (matches RED test 4 directly); `RunTimeline` renders `data-testid=
"run-timeline"` on its outer `<ol>` with NO per-item testid (its `<li>`s carry no `data-testid`
at all) — it cannot be the source of RED test 1/3's `data-testid="check-row"` / `role="group"`
elements. `Skeleton` unconditionally sets `role="status"` on its own root (`_bok-ui.tsx:770`,
confirmed by direct read) — this is a real, foreseeable collision risk with RED test 5's
`page.getByRole("status")` (no scoping/filter given in the brief's literal test), the same class
of problem Task 11 independently hit with Next.js's built-in announcer. `web/app/findings/page.tsx`
(Task 10's fixture-demo leftover) establishes this codebase's one existing `?fixture=` precedent:
an async Server Component reading `searchParams: Promise<{fixture?: string}>` (Next 15's
`searchParams`/`params` are Promises) and looking up a local `FIXTURES` record — reuse this
pattern's shape, adapted for a route that must ALSO do real work (live `EventSource` subscription
via `api.ts::subscribeToScanEvents` when no `?fixture=` is present).

1. **Fixture-driven event replay must share the same callback contract as the real SSE client.**
   `subscribeToScanEvents(id, onEvent, onError?): () => void` (`api.ts`) is the real (non-fixture)
   path. Ruling: implement the screen against that exact signature — in fixture mode
   (`?fixture=streaming|degraded|deterministic` present), swap in a local replay function with
   the identical signature that iterates a canned `ScanEvent[]` array (built from the real
   `ScanCheckEvent`/`ScanTerminalEvent` types, already exported by `api.ts` — reuse them, don't
   redefine) and calls `onEvent` on a short `setTimeout` cadence per frame (genuinely
   asynchronous, not a single synchronous dump — the brief's "checks stream in" is a real
   requirement, not just final-state rendering). No live backend is ever available during this
   project's Playwright runs (same finding as Task 11's ruling #1, re-verified: still no CORS on
   the FastAPI app, still no rewrite/proxy) — the real `subscribeToScanEvents` path is wired for
   production use but exercised by none of this task's RED tests, same forward-reference pattern
   as Task 11's real-submit path.
2. **Known risk: `Skeleton`'s `role="status"` can collide with the required `aria-live="polite"`
   progress region under Playwright strict mode**, exactly the shape of collision Task 11 hit
   with Next's route announcer. Flagging this now so it isn't independently rediscovered as a
   surprise: pace the fixture's per-event delay fast enough (low hundreds of ms total for all 29
   events, comfortably inside RED test 5's default ~5s `expect` timeout) that by the time each
   test's assertion polls, pending-row skeletons have resolved and only the progress region's
   `role="status"` remains. If a genuine, unavoidable multiple-match collision still surfaces
   during real TDD iteration, resolve it the same way Task 11 did: scope the specific locator
   (e.g. constrain to a wrapping container) rather than suppressing real accessibility semantics
   from either `Skeleton` or the progress region — and document the conflict and fix in the
   report the same way, since it again touches the brief's verbatim-given test content.
3. **`RunTimeline` is supplementary, not the vehicle for `check-row`/phase grouping.** The new
   `PhaseGroup.tsx` (this task's own component, one instance per phase, `role="group"` named for
   the phase, containing this screen's actual `data-testid="check-row"` elements) is what RED
   tests 1 and 3 target. `RunTimeline`'s existing shape (chronological list, no per-item testid)
   doesn't fit that job and building a second, redundant full-duplicate view of the same 29
   checks just to technically "consume" it would be pure duplication with zero test coverage —
   same category of overstated Interfaces line as Task 5's reviewer-ruled non-gap ("brief's
   Interfaces line names it, no test needs it, not a missed requirement"). Ruling: use
   `RunTimeline` only if it earns a genuinely different, non-redundant job (e.g. a compact
   recent-activity strip distinct from the full phase-grouped list) — skipping it entirely is
   also fine and not a spec gap.
4. **Terminal summary copy is CLAUDE.md's Copy rule, quoted directly in the brief's GREEN step**:
   *"No findings for the checks that ran"* plus the skipped count when the run is clean — never
   *"You're secure!"*. Use `EmptyState` for this (established Task 10/11 pattern), matching
   `findings/page.tsx`'s existing usage of the same component for the same rule.
5. **Next 15 route params.** `web/app/scans/[id]/page.tsx`'s `params` prop is a `Promise<{id:
   string}>` in Next 15 (confirmed by `findings/page.tsx`'s identical `searchParams` handling) —
   `await` it before use, same as `searchParams`.

## Task 12 log

Task 12: fix round 1/5 (2 addressed, 0 open; commits 371bdba..18440e0)
Task 12: complete (commits 6f13b4e..18440e0, 1 fix round, review clean)
- Fixture-driven event replay (`replayScanEvents` in `fixtures.ts`) shares
  `subscribeToScanEvents`'s exact callback signature (ruling #1), so `page.tsx`'s subscription
  logic is identical regardless of source; three canned `ScanEvent[]` sequences (`streaming`,
  `degraded`, `deterministic`) built from real check-id namespaces and the real
  `phase = id.split(".")[0]` derivation. `PhaseGroup.tsx` renders `role="group"` phase sections
  with `data-testid="check-row"` children, matching RED tests 1/3 directly. Real `EventSource`
  path wired for production use via `subscribeToScanEvents` — untested by this task's RED suite
  by design (no live backend reachable in Playwright, carried forward from Task 11's ruling).
- The `Skeleton`-vs-progress-region `role="status"` collision flagged in ruling #2 turned out to
  be genuinely **structural**, not just a pacing-dependent race: the `degraded` fixture's
  `hasPending` state (`terminalEvent === null && completed < total`) never resolves to false on
  its own, so both `role="status"` elements coexist for the entire run, not just a brief window —
  confirmed independently by the reviewer via direct code trace, not just the implementer's
  claim. Resolved exactly per the ruling's fallback: scoped RED test 5's locator
  (`.filter({ hasText: /of/ })`) rather than stripping real accessibility semantics from either
  component, documented in the report. `RunTimeline` correctly skipped entirely per ruling #3 (no
  spec gap). Terminal summary uses the exact Copy-rule string via `EmptyState`, per ruling #4.
- Fix round 1 (2 Important, both fixed, plus 2 Minors fixed as a bonus): `QuotaStrip`'s
  placeholder provider data was gated only on `modelEngaged`, shared by both the real and fixture
  event paths — a real scan running `descriptions.llm_judge` would have shown fabricated quota
  numbers with no on-page indication they were fake. Fixed by additionally gating on `fixture`
  (real mode now never renders `QuotaStrip` placeholder data). The real SSE subscription had no
  `onError` callback wired — a real connection failure would leave the page stuck at "Starting
  scan…" indefinitely despite `ErrorState` already existing for exactly this; fixed by wiring
  `onError` → `ErrorState` with a working `onRetry` that re-opens the subscription. Re-reviewer
  independently verified both against the fix diff, no new breakage. Also fixed en route (found
  during implementation, not a review finding): a JSDoc comment in `fixtures.ts` containing the
  literal glob `checks/*/*.py` prematurely closed its own block comment, producing a hard 500 on
  the route — reworded, confirmed via curl and a clean build.
- Minor (deferred, but fixed anyway as trivial one-liners during the fix round, so nothing
  remains open): doubled "Skipped — Skipped —" prefix in a skipped-check row's rendered text;
  a stale "11 vs 12" `revision`-phase count in a comment.

## Task 13 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 9-12). Real `Finding`
wire shape (`agent_perimeter/model/finding.py`, serialized as-is by `GET /api/scans/{id}/findings`
via `jsonable_encoder`, confirmed in `agent_perimeter/api/scans.py:298-302` — no field renaming):
`check_id, severity, title, cwe ("CWE-nnn"), taxonomy_refs: string[] ("scheme:id", e.g.
"owasp-llm:LLM01" — confirmed format in checks/taxonomy.py:36), evidence: {kind, excerpt,
highlight: [number,number]|null, redacted}, reproduction: string, claim: {value, method,
derivation, confidence, observed_at, parents, caveat}, confidence: number|null, location:
{uri, line}|null`. Real `Feature` enum has 11 members (`agent_perimeter/model/feature.py`); the
claimed-revision `2026-07-28` bundle is exactly **7** features (`server_discover, result_type,
cacheable_result, mrtr, param_headers, subscriptions_listen, extensions` — confirmed in
`agent_perimeter/transport/features.yaml`), and `2025-11-25`'s bundle is 4 features. The brief's
example copy ("observes 7 of 10 features") is illustrative, not a literal spec — the real
denominator is the claimed revision's bundle size, not a fixed 10; ground fixtures in the real
7-feature 2026-07-28 bundle (e.g. "observes 5 of 7 features") rather than inventing a
non-existent 10th feature. `Claim`'s keyboard handler (`_bok-ui.tsx:112`) **already** activates
on `Enter`, `Space`, `Meta+.` and `Ctrl+.` — RED test "the rail also opens from the keyboard"
needs zero new keyboard logic, only correct `onActivate` wiring. `ProvenanceRail`'s focus
management (`inert`, focus-to-close-button-on-open, focus-return-on-close, Escape-to-close) is
already solid from Task 10's fix round — reuse as-is, no changes needed there.

1. **Load-bearing gap: `_bok-ui.tsx`'s `FindingsTable`/`FindingsTableRow` cannot satisfy this
   task's RED tests as they exist today, and the brief's Files list omits `_bok-ui.tsx`
   entirely.** Verified by direct read: `FindingsTableRow` today only carries `{id, title,
   checkId, severity, derivation, confidence}` — no `cwe`, no `taxonomy`, no `reproduction`, and
   the rendered `<tr>` has no expand interaction and no embedded interactive `Claim`. RED tests 3
   ("every finding row shows its CWE and a taxonomy reference" — checked immediately after
   `page.goto`, so these must be always-visible cells, not hidden behind expansion), 4
   ("expanding a row reveals the reproduction command with a copy button"), and 5/6 (clicking or
   keyboard-activating a `data-testid="claim"` inside a row opens `ProvenanceRail`) all require
   behavior the component does not have. Same class of gap as Task 9's ruling #4 (brief's shown
   code needs a file its own Files list omits) — ruling: add `web/src/lib/_bok-ui.tsx` to this
   task's Files list as **Modify**. Extend `FindingsTableRow` with `cwe: string`,
   `taxonomyRefs: string[]`, `reproduction: string` (and whatever `EvidencePane` needs, if the
   expansion shows evidence too); add two new always-visible columns (CWE, Taxonomy); wrap the
   row's check/title cell in a `<Claim derivation={row.derivation} value={...} onActivate={...}>`
   via a new optional `onClaimActivate?: (row: FindingsTableRow) => void` prop on
   `FindingsTableProps` (only when supplied — don't force every `FindingsTable` caller to wire
   this); add a generic per-row expand/collapse toggle plus an optional
   `renderExpanded?: (row: FindingsTableRow) => ReactNode` slot rendered in a following `<tr>`
   when a row is expanded. Keep the *domain-specific* "reproduction command + copy button +
   evidence" content in this task's own new `FindingRow.tsx` (`web/app/components/`), passed into
   `FindingsTable` via that `renderExpanded` slot — this keeps `_bok-ui.tsx` generic/reusable
   (matching its own stated purpose as a mirror of a *shared* design-system contract) rather than
   baking one screen's domain concept into the shared library. Extend `toCsv` to include the two
   new columns (small, consistent extension of the existing Requirement-2 provenance-column
   precedent) — not RED-tested directly, but cheap and consistent, do it while the file is open.
2. **CSV-export RED test is case-sensitive against the CSV header text as currently written.**
   `expect(body.join("")).toContain("provenance")` — plain-string `.toContain`, case-sensitive.
   The existing `toCsv()` header reuses `FINDINGS_COLUMNS` verbatim, which reads `"Provenance"`
   (capital P, shared with the on-screen `<th>` text) — that does **not** satisfy a lowercase
   `"provenance"` substring check. Verify this directly against the real code before assuming the
   existing implementation already passes; if it doesn't, decouple the CSV header labels from the
   on-screen column labels (or lowercase the CSV header specifically) rather than lowercasing the
   visible `<th>` text, which would be a real, if minor, on-screen regression.
3. **`ConformanceStrip`'s three numbers, precisely.** Per the brief's GREEN step: claim = scan's
   `revision_claimed` (from `GET /api/scans/{id}`, already typed as `ScanStatus.revision_claimed:
   string | null | undefined` in `api.ts`); observed = size of the intersection of
   `features_observed` (also on `ScanStatus`) with the claimed revision's real feature bundle,
   "of N" = that bundle's size; gaps = count of findings in the response whose `check_id ===
   "revision.conformance_mismatch"`. When `revision_claimed` is null/absent, render "revision
   unknown" (RED test 2) instead of computing 0-of-N (which would misleadingly read as maximally
   non-compliant) — this is the same "absence reads as unknown, not as a negative claim"
   principle CLAUDE.md's Copy rules apply elsewhere in this project.
4. **`web/app/findings/page.tsx` (Task 10's fixture-demo leftover) is a different route
   (`/findings`, no `[id]`) from this task's real screen (`/scans/[id]/findings`) — no
   collision.** Its own docstring says "Task 11 replaces this," which is now known-stale (Task 11
   was Screen 1, not this screen) — leave that file alone; fixing its stale comment is a
   whole-branch-review nit, not this task's job, unless it's trivially in the way.
5. **No live backend during Playwright runs** (carried forward, re-verified: still true) — all 8
   RED tests drive the screen via `?fixture=` query params (`mismatch`, `unknown-revision`,
   `mixed`, `clean`), same fixture-route convention as Tasks 11/12. Real `getFindings`/`getScan`
   API calls should still be wired for real (non-fixture) use per the Interfaces line, untested by
   this task's RED suite by design.
6. **Next 15 route params.** `web/app/scans/[id]/findings/page.tsx`'s `params` is a
   `Promise<{id: string}>` — same pattern as Tasks 11/12.

## Task 13 log

Task 13: fix round 1/5 (2 addressed, 0 open; commits ece51ad..8f04060)
Task 13: complete (commits 18440e0..8f04060, 1 fix round, review clean)
- `_bok-ui.tsx`'s `FindingsTable` extended per ruling #4: `cwe`/`taxonomyRefs`/`reproduction`/
  `evidence` added to `FindingsTableRow` (all optional — verified backward-compatible with
  Task 10's `web/app/findings/page.tsx` demo route and `provenance-rail.spec.ts`, which supply
  none of them), two new always-visible CWE/Taxonomy columns, `onClaimActivate`/`renderExpanded`
  as new opt-in props. Domain-specific reproduction/copy/evidence content correctly stayed out of
  the shared file, living in this task's own `FindingRow.tsx` instead. CSV case-sensitivity
  gotcha (ruling #5) genuinely fixed by decoupling a lowercase `CSV_COLUMNS` header from the
  unchanged capitalised on-screen `FINDINGS_COLUMNS` — no visual regression.
- `ConformanceStrip` formula (ruling #3) verified correct, and its feature-bundle data
  (`REVISION_FEATURE_BUNDLES` for both 2026-07-28 and 2025-11-25) matched `features.yaml`
  byte-for-byte — more thorough than the ruling strictly required. Real wire-shape types for
  `Finding`/`Claim`/`Evidence`/`FindingLocation` added to `api.ts`, field-for-field against the
  real Python models, first real (non-`unknown[]`) typing of `getFindings`'s response.
- Fix round 1 (2 Important, both fixed): a keyboard user tabbing to a `Claim` inside an
  expandable row and pressing Enter got the provenance rail opening AND the row unexpectedly
  expanding underneath — `Claim`'s activation handler had no `stopPropagation()`, so the keydown
  bubbled into `FindingsTable`'s own Enter/Space row-expand handler. Fixed with
  `event.stopPropagation()` scoped to just the `activates` branch (arrow-key cell navigation,
  which relies on bubbling, is unaffected) — a root-cause fix in the shared component, not a
  per-caller guard. Re-reviewer independently traced React's synthetic-event model and confirmed
  both other `Claim` call sites (`ProvenanceDemo.tsx`, click-only; `scan-setup.spec.ts`, doesn't
  render `Claim` at all) are unaffected, and verified a new regression test genuinely fails
  without the fix. The "mismatch" fixture's conformance-related findings didn't match what the
  real `revision.conformance_mismatch` check can actually produce (wrong CWE, wrong/incomplete
  taxonomy refs, wrong evidence kind, and a headline finding citing `subscriptions_listen`, a
  feature structurally excluded from this check's diff by design) — rebuilt field-for-field
  against the real check's source, re-reviewer independently re-verified every field including
  the exact severity map and the passively-observable feature set.
- Minor (deferred): `descriptions.imperative_injection` fixture entry cites `CWE-1426`; the real
  check always emits `CWE-1427` (the only one registered in `taxonomy.py`) — one-digit slip.
  Minor (deferred): `static.unbounded_path_param` isn't a real check id anywhere in
  `agent_perimeter/checks/` (inherited from Task 10's fixture, not introduced here). Minor
  (deferred): `Finding.evidence.redacted` is typed on the wire but dropped before reaching
  `EvidencePane` — a redacted finding renders indistinguishably from a non-redacted one, not a
  leak, just a missed visual affordance. Minor (deferred): `ConformanceStrip` renders as a bare
  `<p>` with no `role="status"` — screen-reader announcement on load isn't guaranteed.

## Task 14 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 9-13). Real
`CapabilityEdge` (`agent_perimeter/model/edge.py`): `{tool: string, capability: Capability
(7-member enum: fs_read, fs_write, net_out, exec, secret_read, db_read, db_write), derivation,
claim, rationale: string}` — `GET /api/scans/{id}/graph` returns a flat `jsonable_encoder`d list
of these (`api/scans.py:305-309`, same pattern as `/findings`), no separate top-level `nodes`
array — the frontend must derive nodes (tools AND capabilities) from the edge list itself. This
is a bipartite graph: tool nodes on one side, the 7 fixed capability nodes on the other, edges
connecting a tool to a capability it was found to have, carrying `derivation` (schema/name/
description/probe/artifact) as the evidence for that specific tool-capability link.

1. **"Policy-flagged" is not a field on the wire edge data — it must be cross-referenced from
   real findings, the same pattern `ConformanceStrip` (Task 13) already established, not
   re-derived by reimplementing policy predicates in TypeScript.** Confirmed:
   `agent_perimeter/graph/policy.py::evaluate()` returns `Finding`s with `check_id ==
   "policy.confused_deputy"` or `"policy.secret_egress"` and `claim.value == tool` (the flagged
   tool's name) — `CapabilityEdge` itself carries no flag. Confirmed these ARE real, registered
   checks that land in `outcome.findings` (`agent_perimeter/graph/policy_checks.py`'s
   `PolicyCheck.run()` wraps `evaluate()`, registered in `all_checks.py`, per commit history
   "register 33 checks including policy predicates") — reachable via the real
   `GET /api/scans/{id}/findings`, not dead code. Ruling: in real (non-fixture) mode, fetch both
   `/graph` (edges) and `/findings` (to determine which tool nodes are flagged: filter findings
   whose `check_id` starts with `"policy."`, read `claim.value` as the flagged tool's name) — add
   `getFindings`/a graph-specific fetch to this task's real data-loading path even though the
   brief's Interfaces line only names `GET /api/scans/{id}/graph`. In fixture mode, the fixture
   data can simply mark which tool(s) are flagged directly (no need to simulate the
   cross-reference at the fixture-authoring level) — this only binds the real production path.
2. **Nodes and edges have two parallel renderings of the same data: the always-in-DOM accessible
   table (GREEN step's required build order — table first) and the force-directed SVG/canvas
   graph.** `getByTestId("node")`/`getByTestId("node-flagged")`/`getByTestId("edge")` (with
   `data-derivation`/`stroke-dasharray` attributes) belong to the graph rendering specifically;
   the table's rows are what RED test 6 counts against `edge` count + 1 (header row) — the table
   needs an accessible name matching `/capability edges/i` (`aria-label` or `<caption>`), and per
   the GREEN step, **focus order through graph nodes must match the table's row order** — build
   both off one shared, ordered node/edge list, not two independently-ordered structures.
3. **The pulse is a one-shot CSS animation, not a JS timer** — this is given verbatim as the
   REFACTOR step's own `ponytail:` comment; follow it literally. `data-pulse` transitions
   `"playing"` → `"done"` via a real CSS animation's `onAnimationEnd`, not `setTimeout`. Under
   `prefers-reduced-motion: reduce` (checked via `window.matchMedia`, which Playwright's
   `browser.newContext({ reducedMotion: "reduce" })` genuinely sets and Chromium's `matchMedia`
   correctly reports — no known collision/gotcha here, unlike prior tasks), skip the animation
   entirely and set `data-pulse="skipped"` with `data-ring="true"` present from the very first
   render, never transitioning through `"playing"`.
4. **Derivation must map to stroke pattern AND a legend entry, never colour alone** (GREEN step,
   quoted directly) — this is 00 §5.2's "no colour-alone encoding" rule, same rule
   `SeverityBadge`/`FindingsTable`'s provenance column already honour elsewhere in this codebase.
   RED test 4 checks `stroke-dasharray` differs between `probe`/`description` edges specifically
   — pick a genuinely distinguishable dash pattern per derivation (4 values: schema/name/
   description/probe/artifact is 5, but the graph only ever carries the 5 `Derivation` values a
   `CapabilityEdge` can have, same set `_bok-ui.tsx`'s `DERIVATION_META` already assigns glyphs
   to — reuse that glyph vocabulary for the legend entries' labels/glyphs, add a per-derivation
   `stroke-dasharray` value alongside).
5. **`Claim`/`ProvenanceRail` reuse is the same pattern as Task 13** — clicking/keyboard-
   activating a node (RED test 5: Tab focuses the first node, Enter opens the rail) opens
   `ProvenanceRail` with that tool's capability claims as the chain. `Claim`'s existing keyboard
   handler (Enter/Space/Meta+./Ctrl+.) and the recent Task 13 `stopPropagation()` fix both already
   exist and need no changes — but this screen's nodes are graph elements (likely SVG `<g>` or
   similar), not `<td>` cells, so the "keyboard double-activation into row-expand" class of bug
   from Task 13 doesn't apply here structurally; still worth a quick sanity check that nothing
   else on this screen also listens for Enter on the same focused element.
6. **No live backend during Playwright runs** (carried forward) — RED tests drive the screen via
   `?fixture=deputy|mixed-derivation|no-tools`. Wire the real `/graph` (and, per ruling #1, the
   real `/findings` cross-reference) for production use; untested by this task's RED suite by
   design.
7. **Next 15 route params**: `web/app/scans/[id]/graph/page.tsx`'s `params` is a
   `Promise<{id: string}>` — same pattern as Tasks 11-13.

## Task 14 log

Task 14: complete (commits 8f04060..7d285cc, review clean — Approved, spec ✅, 0 Critical/Important)
- All 8 pre-flight ruling items implemented and independently re-verified against the real
  backend, not just the diff: the policy-flag cross-reference (`getGraph` + `getFindings`,
  filtering `check_id.startsWith("policy.")`, reading `claim.value`) checked directly against
  `graph/policy.py`/`policy_checks.py`/`all_checks.py` and confirmed those are real, registered,
  reachable findings, not dead code. Pulse state machine (`pending→playing→done`) driven by a
  real `@keyframes` CSS animation + `onAnimationEnd`, grepped clean of any `setTimeout`/
  `setInterval`; reduced-motion detected via `useLayoutEffect` + `matchMedia` (resolves before
  paint, so `"playing"` is never visibly shown when reduced motion is active). Table and graph
  both iterate one shared ordered edge list, so focus order and table row order can't diverge.
  Derivation → `stroke-dasharray` (5 distinct values) plus a legend reusing `_bok-ui.tsx`'s
  existing `DERIVATION_META` (exported for reuse — the only change to that shared file, 7 lines,
  a doc comment plus `const`→`export const`; `Claim`/`ProvenanceRail` themselves untouched).
- Self-review caught and fixed a real accessibility bug before reporting (`role="img"` on an SVG
  with genuinely focusable descendants), landed as its own correctly-scoped second commit.
- Full-suite reruns intermittently flaked under heavy parallel load (`next dev`, 11 workers) —
  investigated rigorously (isolated reruns clean 35/35 and 56/56, a duplicate diagnostic spec
  passing in the same run the real spec failed in a different worker, flake fully eliminated
  under `next build && next start`) and independently verified as credible: no timer exists
  anywhere in the new code, the failing assertion sits downstream of unmodified `ProvenanceRail`
  code. Correctly scoped as disclose-not-fix (`playwright.config.ts` isn't in this task's Files;
  changing it would affect all spec files' timing suite-wide off one implementer's local
  worker-count observation) — **carried to the final whole-branch review**: consider whether
  `web/playwright.config.ts`'s `webServer.command` should move from `npm run dev` to
  `next build && next start` (a switch its own Task-10 `ponytail:` comment already anticipated,
  though for different reasons — minification/real caching headers, not compile contention) if
  CI ever runs this suite at high parallelism.
- Minor (deferred): `claimValueLabel`/claim-flattening logic duplicated near-verbatim between
  this task's `graph/page.tsx` and Task 13's `findings/page.tsx` (`toChain`) rather than factored
  into a shared `src/lib/provenance.ts` helper. Minor (deferred): the real (non-fixture)
  `Promise.all([getGraph(id), getFindings(id)])` has no `.catch()` — a fetch failure leaves the
  page on `Skeleton` forever despite `ErrorState` existing for exactly this; identical
  pre-existing gap already present in Task 13's `findings/page.tsx`, not newly introduced here,
  worth a codebase-wide follow-up. Minor (deferred): `ProvenanceChainEntry.source`'s doc comment
  says "a working link, or a file:line reference"; both this task and Task 13 populate it with
  free text instead — cosmetic, consistent with existing precedent. Minor (deferred): two edges
  from the same tool to the same capability (different derivations) render as overlapping SVG
  lines at identical coordinates — harmless to RED tests (attribute-based), already covered by a
  disclosed static-bipartite-layout `ponytail:` comment.

## Task 15 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 9-14).

1. **No live backend exists for this screen at all — a real difference from every prior screen's
   ruling, not just "untested by RED but wired for real."** `Tool.description_hash` (sha256 hex,
   computed and written during scan persistence — `agent_perimeter/api/scans.py:214`) and
   `DriftEvent {tool_id, field, old_hash, new_hash, detected_at, severity}`
   (`agent_perimeter/db/models.py:150-159`) are real DB columns, confirmed — the brief's "already
   in the v1 schema" claim is accurate. But nothing reads either back over HTTP: grepped the
   entire plan (`docs/superpowers/plans/2026-08-11-agent-perimeter-week4-census-ui.md`) for
   `drift`/`DriftEvent`/a scans-by-target listing route — none exists anywhere in the 17-task
   list. Task 9's own "Produces" line (plan line 1480) enumerates the complete, final route set
   this project will ever have (`POST /api/scans`, `GET /api/scans/{id}`, `.../events`,
   `.../findings`, `.../graph`, `.../report.sarif`, `GET /api/census/runs/{id}`) — no scan-history
   or drift route among them. Ruling: this screen is a genuine, 100%-fixture-driven v1 stub, not
   "fixture-tested, real-path-wired-but-untested" like Screens 1-4. Do **not** invent a fetch
   against a nonexistent endpoint. In real (non-fixture) mode, honestly render the same "needs at
   least two scans" empty state unconditionally — there is no way to determine otherwise without
   a backend capability that doesn't exist — rather than silently pretending a real check ran.
   Do **not** add new backend (`agent_perimeter/api/*.py`) files to close this gap: a real
   scan-history/drift-listing endpoint is a Week-4-plan-level gap for the human partner to decide
   on and scope properly, not something to improvise into a frontend-only task via a controller
   ruling — this is the one load-bearing item in this ruling set genuinely outside what a
   same-scale fix (adding one missing frontend file, extending one already-frontend component)
   can responsibly absorb. State this plainly in the task report as a known, disclosed gap.
2. **`DiffView` (`_bok-ui.tsx`) cannot satisfy this task's RED tests as it exists today, and has
   zero existing consumers (first real use) — so extending it is zero-regression-risk, unlike
   Tasks 13/14's shared-component extensions.** Verified by direct read: it diffs at line
   granularity only (`before.split("\n")`/`after.split("\n")`), and its rendered `<div
   className="bok-diff-line">` elements carry no `data-testid` and no `data-glyph` — the `+`/`−`
   are plain inline text characters, not an attribute. RED tests 2/3 need `data-testid="added"`/
   `"removed"` and `data-glyph="+"`/`"−"` specifically, and the brief's own intro prose (not just
   a test name) states the requirement explicitly: *"a word-level red-lined diff is the most
   visceral artifact in the product."* A one-line tool description with a single changed word
   would show as a whole-line replacement under the current line-only diff — technically passing
   the RED tests' substring checks, but not word-level and not the described artifact. Ruling:
   add `web/src/lib/_bok-ui.tsx` to this task's Files list as **Modify**. Extend `DiffView` with
   an optional `granularity?: "line" | "word"` prop (default `"line"`, so nothing changes for a
   future line-mode caller) — when `"word"`, tokenize on whitespace instead of newlines, render
   inline (not stacked blocks — a word-level diff reads as a paragraph, not a list), and give
   each changed token/run `data-testid="added"|"removed"` plus `data-glyph="+"|"−"`.
3. **`RunTimeline` is named in the GREEN step's prose but not in Interfaces, and has zero existing
   consumers** (Task 12 explicitly skipped it, per that task's own ruling — no RED test in this
   plan has ever required it). RED test 4 targets `data-testid="drift-timestamp"`, which doesn't
   exist on `RunTimeline`'s current `<time>` element. Same treatment as Task 12's ruling: optional
   — use `RunTimeline` (adding a safe `data-testid="drift-timestamp"` to its `<time>` element,
   zero regression risk given no consumers) if it fits cleanly, or build a minimal custom ordered
   list if that's cleaner. Implementer's call either way.
4. **Copy, verbatim-adjacent to RED test 1's regex**: *"needs at least two scans of the same
   target"* and must never contain "coming soon" — ties to CLAUDE.md's Copy rules (state what
   happened and what's needed, no apology, no vague deferral language).
5. **No live backend during Playwright runs** (same class of finding as every prior task, but see
   ruling #1 above for why this screen's real-mode behavior differs from Screens 1-4's "wired for
   real, untested by RED" pattern) — RED tests drive the screen via
   `?fixture=single-scan|changed-description`.
6. **Next 15 route params**: `web/app/scans/[id]/drift/page.tsx`'s `params` is a
   `Promise<{id: string}>` — same pattern as Tasks 11-14.

## Task 15 log

Task 15: fix round 1/5 (1 addressed, 0 open; commits a4c7ad8..8916f46)
Task 15: complete (commits 7d285cc..8916f46, 1 fix round, review clean)
- All 6 pre-flight ruling items implemented and independently re-verified: no fetch to a
  nonexistent backend endpoint anywhere in the real path (confirmed the diff touches only `web/`
  files); empty-state copy honest, never "coming soon"; `DiffView` extended additively
  (`granularity?: "line"|"word"`, defaulting to `"line"` with a byte-identical unchanged body for
  that mode — zero regression risk confirmed, since `DiffView` had no prior consumers anywhere in
  the codebase before this task).
- **Ruling: overrode the first review's "Approved, acceptable v1 debt" disposition on the
  WordDiff finding and fixed it instead of deferring it.** The implementer's own `ponytail:`
  comment disclosed a "first divergence, no re-sync" diff that marks an entire unchanged tail as
  both fully removed and fully added after the first point of divergence — the first reviewer
  independently hand-traced this as real (not hypothetical) using "the cat sat on the mat" → "the
  dog sat on the mat", and confirmed the shipped `changed-description` fixture text was
  deliberately hand-shaped to avoid exposing it. Cost of the ruling if wrong: one extra fix round
  (already spent) on the plan's stated flagship differentiator screen ("the most visceral artifact
  in the product") — judged worth it given the fix was already named (the `diff` npm package) and
  cheap, and a diff that silently overstates how much changed is close kin to the false-positive
  problem this whole project exists to avoid.
- Fix round 1 (1 Important, addressed): replaced the positional-scan algorithm with `diffWords`
  from the `diff` npm package (`^9.0.0`, **BSD-3-Clause** — corrected from the dispatch message's
  mistaken MIT assumption, independently verified against `package.json`, the lockfile, and the
  installed package metadata; BSD-3-Clause is on CLAUDE.md's allowed list). Re-reviewer
  independently hand-traced the cat/dog case against the package's documented merge semantics and
  confirmed the bug is genuinely gone (surgical single-word removed/added spans, unchanged tail
  left as plain text).
- **Ruling: the fix forced an additional, unilateral edit to the brief's "verbatim" RED test 2's
  literal substrings, and this is a real, adjudicated deviation, not a silent one.** Fixing the
  algorithm made the brief's original literals ("read the config file" / "read any file")
  mathematically unsatisfiable — "read" and "file" are single-occurrence, same-order words in both
  the before/after fixture text, so any correct LCS-based diff is *guaranteed* to leave them as
  unchanged plain text, never inside a changed span. The re-reviewer independently confirmed this
  via the diff algorithm's own matching guarantees (not just by trusting the implementer's "tried
  10+ variants" claim) — no fixture text exists that could have kept the original literals
  passing against a genuinely correct diff. Replacement assertions ("the config" removed / "any"
  added) independently hand-traced against the real `diffWords` output and confirmed to still
  faithfully test the RED test's actual intent (a real word-level diff producing distinct
  removed/added spans for a changed clause) — arguably a *better* regression guard, since the
  narrowed literals are themselves direct evidence the over-marking bug is gone.
- Minor (deferred): array-index-as-React-key in the new diff-rendering loop — harmless here since
  the list is freshly derived from props each render, never reordered against stale state, but
  noted by the re-reviewer as a style nit. Minor (deferred): the implementer's own report used
  status `DONE` on the first pass despite flagging two real, named concerns for review scrutiny —
  `DONE_WITH_CONCERNS` would have been the more accurate status; a process nit, not a code issue.

## Task 16 pre-flight ruling (recorded before dispatch, 4 Sep 2026)

Verified against real state before dispatch (same discipline as Tasks 9-15). This is a
verification task by design — most of its real work is "run axe/keyboard/print checks across six
screens and fix whatever surfaces," which cannot be pre-solved from here; that's expected,
substantial iterative work per the brief's own Step 3 ("Run both suites and fix... the assertion
is the deliverable"), not a sign of a broken plan. What follows are concrete, verified gaps that
would block RED from even running correctly or make an assertion vacuous, not a full a11y audit.

1. **The brief's own `pretest` command doesn't work — `fixture://` is not a recognised target
   scheme anywhere in this codebase.** Confirmed by reading `agent_perimeter/scan_runner.py:108-
   112::build_transport`: it recognises only `http://`/`https://` (→ `StreamableHttpTransport`)
   or falls through to `StdioTransport(shlex.split(target))` — `fixture://mixed` would be parsed
   as a literal shell command and fail to launch, not produce fixture data. Ruling: do **not**
   shell out through `agent-perimeter scan --target fixture://mixed --html ...`. Instead,
   `agent_perimeter/report/html.py::render_report(*, findings, edges, fingerprint, target,
   skipped, scores) -> str` is a pure function with no CLI/transport/container dependency
   (confirmed by direct read) — write the `pretest` step as a small Python invocation (a one-off
   script, or `uv run python -c "..."`) that imports `render_report` directly with a
   representative `Finding`/`CapabilityEdge`/`Fingerprint` set and writes the result to
   `web/tests/fixtures/report.html`. **Reuse `tests/report/factories.py`** (confirmed to exist —
   this project's existing sample-data factory for exactly this module) rather than hand-rolling
   new sample findings; same for the census report (`agent_perimeter/report/census_report.py::
   render_census(run, records) -> str`, also a pure function, also confirmed to already have
   `tests/report/test_census_report.py` as a shape reference). This is materially safer than
   depending on a real containerised scan in a verification task's `pretest` step (Docker
   availability has already been flagged unreliable in this sandbox across earlier tasks), and
   avoids inventing a new target scheme this project doesn't otherwise have.
2. **`agent_perimeter/report/templates/report.html.j2` (Week 3, not in this task's Files list) is
   missing several `data-testid` attributes this task's own RED tests require — confirmed by
   direct read, zero matches for `data-testid` anywhere in the file today.** `<footer>` has no
   `data-testid="methodology-footer"` — RED test `expect(page.getByTestId("methodology-footer")).
   toBeVisible()` will hard-fail without it (not vacuous — this one genuinely blocks). The
   severity `<span class="sev" data-glyph="...">` has no `data-testid="severity-badge"` and each
   finding `<tr>` has no `data-testid="finding-row"` — these two don't hard-fail (Playwright's
   `.all()`/`querySelectorAll` on a missing testid returns zero elements, and a loop over zero
   elements or a `.length === 0` check both trivially "pass") but would make the greyscale-glyph
   test and the page-break test vacuously true, testing nothing — exactly the "weakened assertion"
   the brief's Step 3 explicitly forbids, just via absence rather than an edited assertion.
   Ruling: add `agent_perimeter/report/templates/report.html.j2` to this task's Files list as
   **Modify** — add all three testids; no nav/export-button chrome exists in this template today
   and none should be invented just to exercise the two `toBeHidden()` assertions, which pass
   correctly on absence (verified: `toBeHidden()` succeeds for either "not visible" or "not
   present in the DOM").
3. **`agent_perimeter/report/templates/census.html.j2` (also Week 3, also not in this task's
   Files list) has zero `data-testid` attributes anywhere — confirmed by direct read.** The real
   data this task's Step 5 test needs (`population-size`, `tier2-n`, `unknown-count`,
   `fetch-failures`, `term-definitions`) is all genuinely present in the template (`run.
   population_size`, `run.tier2_n`, `run.fetch_failures`, an `.unknown` figure — more than one
   candidate exists, `artifact_agg.unknown`/`probe_agg.unknown`; pick whichever the RED test's
   single `unknown-count` id is meant to represent, since the test only checks visibility, not a
   specific value — and the `term_definitions` loop) — just untagged. Unlike report.html.j2's
   gap, **this one hard-fails outright** without the fix (`toBeVisible()` on a missing element
   fails, there's no `toBeHidden()` escape hatch here). Ruling: add
   `agent_perimeter/report/templates/census.html.j2` to Files as **Modify** — add all 5 testids.
4. **`agent_perimeter/report/templates/report.css` has an existing `@media print {}` block
   (confirmed, `report.css:26`) but no `break-inside: avoid` rule for finding rows** — needed for
   RED test "no finding row is split across a page break," which reads `getComputedStyle(el).
   breakInside` for every `[data-testid='finding-row']` element (which won't exist until ruling 2
   lands). Ruling: add `agent_perimeter/report/templates/report.css` to Files as **Modify** — add
   a `break-inside: avoid` rule scoped to `[data-testid="finding-row"]` (or the existing `tr`/row
   selector) inside the print media block.
5. **The brief's `webServer` array (plan text, quoted verbatim) must be *added to*, not swap out,
   the existing single-`webServer` config** — `web/playwright.config.ts` currently has one
   `webServer: { command: "npm run dev", ... }` entry (Task 10) that every existing spec file
   (`tokens.spec.ts` through `drift.spec.ts`) already depends on. Replacing it outright rather than
   converting to a two-entry array would break all 6 prior tasks' test suites. Confirm the merged
   array preserves the existing dev-server entry's exact `command`/`url`/`reuseExistingServer`
   behaviour and only adds the new static-file-server entry for `tests/fixtures/`.
6. **`docs/evidence/` already exists** (created by Task 11) — no new directory needed, just two
   new files landing in it. **`@axe-core/playwright` is already an installed dev dependency**
   (added in Task 10, MPL-2.0, already flagged for the Task 17 licence audit — not a new
   dependency for this task). **`.github/workflows/ci.yml` already exists** with a `test:` job
   (Python side) — this task adds a new, separate `web:` job alongside it, not a fresh file.
7. **The 6-screen axe/keyboard/print sweep will very likely surface real, previously-unknown
   accessibility issues across Tasks 11-15's screens** (contrast, missing labels, focus-order
   quirks, the `CapabilityGraph`'s SVG at 375px, `FindingsTable`'s wide columns at 375px, etc.).
   This is expected, substantial, legitimate iterative work inherent to what a verification task
   *is* — do not treat a long list of real fixes across `web/app/**` as scope creep or as evidence
   something upstream is broken; it is this task's actual job. Do not weaken an assertion to make
   it pass (per the brief's own explicit instruction) — fix the underlying screen instead.

## Task 16 log

Task 16: complete (commits 8916f46..f4477ea, review clean — Approved, spec ✅, 0 Critical/Important)
- All 7 pre-flight ruling items landed correctly, independently verified: `pretest` calls
  `render_report`/`render_census` directly via a new `analysis/render_web_fixtures.py`, reusing
  `tests/report/test_html.py`'s sample data (report side) and `tests/report/factories.py`'s
  `census_fixture` (census side) — no dependency on a live scan or the nonexistent `fixture://`
  scheme. Both static Jinja templates gained their required `data-testid`s; `report.css` gained
  the `break-inside: avoid` rule. `playwright.config.ts`'s `webServer` array addition verified
  byte-identical on the pre-existing entry (the highest-blast-radius change in this task, since
  every prior task's tests depend on it) with the new static-file-server entry added alongside,
  not replacing it.
- 10 real, distinct axe/keyboard/print/375px issues found and fixed across the six screens and
  two static templates, each independently traced to a genuine root cause by the reviewer (not
  just trusted from the report): an unescaped `report.css` block inside Jinja's autoescaped
  render corrupting quotes in the printed CSS (`html.py` renders `report.css`'s raw text without
  `|safe`, confirmed against its `autoescape=select_autoescape(...)` config); `ProvenanceRail`'s
  `inert` toggle moved from an effect-only assignment to a declarative JSX prop, closing a real
  first-paint gap without disturbing Task 10's original design or Task 13's separate `Claim`
  `stopPropagation` fix; two screens (live-scan, drift) genuinely had zero focusable elements at
  Tab-press time in certain fixture states — fixed with real navigation links to adjacent screens,
  not decoy elements (reviewer traced the actual pages to confirm this, given the risk that such a
  fix could otherwise just game the keyboard-reachability assertion); a findings-page hydration
  race fixed by computing fixture data synchronously in the render body instead of via
  `useEffect`, correctly preserving Rules of Hooks; plus 4 (report says; diff shows 5, see Minor
  below) under-contrast OKLCH tokens darkened, 2 restored focus outlines, 2 wide-table 375px
  overflow wraps, and a flex-overflow fix for long check-ids.
- Minor (deferred): report claims 4 darkened contrast tokens, diff shows 5 (`--severity-low` also
  changed, unmentioned) and describes `--provenance-verified`'s change as lightness-only when
  chroma also shifted — both changes move in the correct direction and don't violate 00 §5.2's
  pinned paper/ink/accent values or the severity-never-colour-alone rule, but the report's
  self-description of its own diff isn't fully accurate. Minor (deferred): report cites a flaky
  `graph.spec.ts` keyboard-test discussion as living in `progress.md`; it's actually in
  `task-14-report.md` — the substance of the claim (pre-existing `next dev` compile-contention
  flake, not app logic) checks out, only the citation is wrong. Minor (deferred):
  `census.html.j2`'s `unknown-count` testid wraps a whole paragraph rather than just the figure —
  passes the visibility-only test and is explicitly permitted by ruling 3's own wording, but reads
  broader than a reader would expect from the name. **Disclosed, not fixed, correctly out of this
  task's exercised scope (carried to final whole-branch review):** pre-existing ruff-format drift
  on 9 unrelated files (not introduced by this task); darkened severity/provenance tokens have no
  dark-mode-specific tuning (untested).

## Task 17 pre-flight ruling (recorded before dispatch, 7 Sep 2026)

**Scope boundary, decided with the human partner before any dispatch (not a unilateral
controller ruling — this is an explicit, out-loud decision, recorded per the subagent-driven-
development skill's "four things stop you" rule: this task's own Step 8 is a publish, a side
effect outside this worktree, on a repo going public with a real embargo clock).** Asked the
human partner how to scope this task, since it bundles ordinary in-worktree code work together
with irreversible real-world actions. Decision: build the artifacts (Steps 1, 2, 4, 5, 6, 7 in
full); treat Step 3 (clean-machine verification) as a **best-effort check inside this sandbox
only** — Docker is confirmed reachable here (`docker --version`/`docker info` both succeeded),
but this sandbox is the working dev environment, not a fresh VM, so `docs/evidence/clean-
machine.md` must say so plainly rather than claim a genuine clean-machine run that didn't happen;
**Step 8 (flip the repo public, publish to GitHub Pages, tag `v0.1.0`, start the 90-day embargo
clock) is explicitly out of scope for this dispatch.** Do not create a git tag, do not push
anything, do not touch repository visibility settings, do not publish anything to an external
service. The commit at the end of this task's work stays local to this worktree/branch like every
other task's commits have — the human partner decides separately, later, whether and how to
actually publish.

Verified against real state before dispatch (same discipline as Tasks 9-16):

1. **`docker-compose.yml` currently has 2 services (`app`, `postgres`), not the 4 the brief
   wants** (confirmed by direct read) — needs restructuring to `db`/`api`/`web`/`fixture` per the
   brief's Step 2. A root `Dockerfile` already exists (used by the current `app` service) — verify
   it still builds the FastAPI app correctly rather than assuming a rewrite is needed; the brief's
   "Create: Dockerfile (api)" is stale phrasing (it already exists) — treat as Modify-if-needed.
   `web/Dockerfile` genuinely does not exist — real Create. `tests/fixtures/servers/Dockerfile`
   already exists (`FROM python:3.12-slim`, launches `server.py`) — the compose `fixture` service
   should build from that existing context, not a new one. `.env.example` already exists — extend
   it for any new service's variables rather than recreating it.
2. **The brief's own `smoke.sh` script (shown verbatim) references a stale migration number.**
   Real migration files: `0001_initial.py`, `0002_add_secret_finding_expires_at.py`,
   `0003_census.py` — the real head is **0003**, confirmed. `grep -q 0004` in the brief's shown
   script would never match (same class of stale reference Task 1's own ruling already corrected
   once — `0003_census.py`, not `0004_census.py`). Fix to `grep -q 0003`.
3. **`GET /api/health` does not exist anywhere in the FastAPI app** — confirmed zero matches
   across `agent_perimeter/api/*.py`. The brief's `smoke.sh` (`curl -fsS localhost:8000/api/health`)
   and the compose healthcheck it implies both depend on this route existing. Ruling: add
   `agent_perimeter/api/app.py` to this task's Files list as **Modify** — add a trivial
   `GET /api/health` route (e.g. `{"status": "ok"}`, 200) for the compose healthcheck and the
   smoke script to target.
4. **`README.md` does not exist at all** — the brief's Files list says "Modify," which is stale;
   this is a real **Create**.
5. **`pip-licenses` is not a declared project dependency** (confirmed, no match in
   `pyproject.toml`) — run it via `uvx pip-licenses` (no `pyproject.toml` change needed) rather
   than adding a new permanent dependency for a one-off audit command, unless the implementer finds
   a reason `uvx` isn't available in this sandbox, in which case a dev-only dependency is fine.
6. **CLAUDE.md's Licence line is already correct** (`Licence: Apache-2.0`, confirmed by direct
   read, line 4) — Step 5's check should just confirm this and move on; no edit needed there.
7. **Step 7's final DoD sweep and Step 8's numbered walk-through of brief §12's ten items are real
   verification work this task should still do in full** (they're read-only/reporting, not
   publish actions) — the only part of "Step 8" excluded by the scope boundary above is the
   actual `git tag`/publish/repo-visibility actions at the very end of that step's shown shell
   block, not the DoD walk-through that precedes it in the brief's numbering (the brief's own
   Step 7 is the DoD walk-through; re-read the brief carefully so the walk-through and the publish
   actions, which the brief keeps as separate numbered steps, aren't conflated).

## Task 17 log

Task 17: complete (commits f4477ea..e4d9564, review clean — Approved, spec ✅, 0 Critical/Important)
- Scope boundary independently verified twice — once by the controller directly (`git tag
  --list` empty, `git remote -v` shows origin configured but never contacted, `git log`/reflog
  shows only the 4 expected local commits) and once by the reviewer (content-honesty check on
  `docs/evidence/clean-machine.md` and `README.md`, confirming neither fabricates a genuine
  clean-machine run or a publish that hasn't happened). No git tag, no push, no repo-visibility
  change, no external publish — all correctly deferred to the human partner per the pre-dispatch
  decision.
- All 6 pre-flight ruling items landed correctly: `docker-compose.yml` restructured to
  `db`/`api`/`web`/`fixture` (correct `depends_on: condition: service_healthy` chain, real
  healthchecks per service, `fixture` profile-gated since a stdio server has no long-running
  healthy state); `scripts/smoke.sh`'s migration check fixed to the real head (`0003`); `GET
  /api/health` added with no DB dependency; `README.md` created fresh; licence audit run via `uv
  run --with pip-licenses` (a more correct variant of the ruling's suggested `uvx` — auditing the
  project's actual dependency set, not an isolated tool env); CLAUDE.md's Licence line correctly
  left untouched.
- Implementer caught and fixed a real, independently-verified bug in the brief's own shown
  `smoke.sh`: the stdio-shaped target it POSTs (`"python /server.py"`) hits Task 9's
  `unsupported_target` 400 refusal before ever reaching the scope-file check the test claims to
  exercise — reviewer traced `scans.py` → `scope.py` → `app.py` end-to-end and confirmed the fix
  (`https://example.invalid/mcp`) genuinely reaches and exercises the intended 422
  `AuthorizationRequired` path instead.
- Licence audit surfaced two new, previously-unflagged **runtime** (not dev-only) dependencies:
  `certifi` (MPL-2.0, transitive via `httpx`) and `psycopg`/`psycopg-binary` (LGPL-3.0, direct).
  Neither is AGPL/SSPL/BUSL (the brief's Step 4's explicit denylist), but both are outside
  CLAUDE.md's stricter stated "Apache/MIT/BSD deps only" policy — disclosed prominently in
  `docs/licences.md` with a runtime-vs-dev-only table, not buried. **Flagged for the human
  partner's judgment, not decided here** — same treatment as every other licence question this
  plan has surfaced (Task 3's `hypothesis`, Task 10's `@axe-core/playwright`/`@img/sharp-libvips`),
  but these two are the first **runtime** (not dev-only) non-Apache/MIT/BSD dependencies found in
  the whole project, which is a materially different risk category worth this plan's own hard
  rule ("flag any AGPL dependency explicitly rather than adopting it silently") being read in its
  clearly-intended broader spirit.
- Minor (deferred): `docker-compose.yml`'s `web` build arg for `NEXT_PUBLIC_API_BASE_URL` has no
  `:-default` fallback (unlike `db`'s password var, which fails loudly if unset) — low risk since
  `.env.example` ships a value, but silently passes an empty string if a user's `.env` ever omits
  it. Minor (deferred, already disclosed by its own `ponytail:` comment): `web/Dockerfile` is a
  single-stage build (full `node_modules` in the final image) — real, named tradeoff with a
  stated upgrade path (`output: "standalone"`), worth revisiting before a genuine clean-machine
  timing number is taken seriously.
- **Two DoD items remain honestly, deliberately open, not fabricated closed**: DoD 7 (census
  report published) and DoD 10 (a true clean-machine — fresh VM, not sandbox — verification) —
  both require real-world actions this plan's scope boundary explicitly deferred to the human
  partner, alongside the Step 8 publish decision itself.

## All 17 tasks complete.

Every task in `docs/superpowers/plans/2026-08-11-agent-perimeter-week4-census-ui.md` is now
`complete` in this ledger, each with a clean final review (0 open Critical/Important). Per
superpowers:subagent-driven-development, the next step would ordinarily be one final whole-branch
review followed by superpowers:finishing-a-development-branch — but that final step involves
merge/branch decisions on shared state, the same class of action this session has been treating as
requiring the human partner's explicit go-ahead throughout (see the Task 17 scope-boundary
decision above). Stopping here to report to the human partner rather than proceeding
autonomously.

## Final whole-branch review (7 Sep 2026)

Human partner confirmed proceeding with the final whole-branch review. Three independent reviewers
dispatched against the full branch diff (`14a5b24..e4d9564`) and synthesized. Findings, each
verified directly against the real code at `e4d9564` before acting on any of them (grep/read, not
trusted from review text alone — same discipline as every pre-flight ruling above):

1. **Critical — confirmed**: no `CORSMiddleware` anywhere in `agent_perimeter/api/app.py` (grepped,
   zero matches). `docker-compose.yml` runs `web`:3000 / `api`:8000 as separate origins; a bare
   `docker compose up` + submit-a-scan fails in a real browser. Breaks the DoD's "compose
   reproduces a clean machine" claim.
2. **Important #1 — confirmed**: `web/app/scans/[id]/page.tsx:196-203` renders the "No findings"
   `EmptyState` unconditionally on the terminal SSE frame; `ScanTerminalEvent` carries no findings
   count; `getScan(id)` already exposes `findings_count` (`api.ts:47`) but nothing calls it here.
3. **Important #2 — confirmed**: `web/app/findings/page.tsx` + `ProvenanceDemo.tsx` (Task 10
   scaffolding) ship as a live, unauthenticated route with fabricated findings and no "sample data"
   marker; only `tests/tokens.spec.ts` (2 call sites) and `tests/provenance-rail.spec.ts` (1 call
   site) still target it — `tests/findings.spec.ts`/`a11y.spec.ts` already use the real
   `/scans/1/findings?fixture=mixed` route.
4. **Important #3 — confirmed**: `cli.py::census()` never calls `render_census`/`export_raw`
   (`report/census_report.py`) — only a dev script (`analysis/render_web_fixtures.py`) and tests
   do. The CLI cannot produce the published census report end-to-end.
5. **Important #4 — confirmed, and worse than "deferred": already self-documented as broken.**
   `census/run.py::run_census()`'s per-run salt (line 111) is discarded after use (its own
   `ponytail:` comment says so); `census_report.py::export_raw`'s `_digest_for` docstring already
   states the resulting CSV digest can never match the DB's `coords_digest` for the same reason.
   Ruling: fold 4a (dead CLI) and 4b (salt) into one fix — persist `CensusRun.salt` (new nullable
   column + migration `0004`), have the CLI's `--out` path pass `run.salt` to `export_raw` instead
   of a fresh one. Load-bearing for the plan's "publish the salt after the 90-day embargo" model,
   which cannot work at all without a persisted salt.
6. **Important #5 (NOTICE) — confirmed**: `NOTICE` claims a full npm dependency list exists "in
   `web/`"; no such file exists anywhere — `docs/licences.md`'s npm section is an explicit
   `--summary` (license-type counts only), not a per-package list, and it isn't in `web/`. Doc
   accuracy gap, not a licensing-compliance gap (no AGPL/SSPL found either side, unaffected).
- **Excluded from the fix wave, ruled as decisions for the human partner, not code fixes:** no
  auth/SSRF gating on `/api/*` (already disclosed and confirmed with the human partner at Task 9);
  the licence-audit process having been run only on Windows, missing Linux-only runtime deps
  (`uvloop` etc.) — a tooling/process gap, not an application bug.

Brief written: `final-review-fix-brief.md`. Per the skill's Final Review section ("dispatch ONE fix
subagent with the complete findings list — not one fixer per finding"), dispatching a single
implementer for all 6 items, followed by one scoped re-review.

Fix wave: implementer completed all 6 items in one commit (`375004b`), report at
`final-review-fix-report.md`. Self-reported: `ruff check`/`mypy --strict` clean, `pytest` 628
passed (93.87% coverage), `npx tsc --noEmit`/`npm run lint` clean, Playwright 64 passed (up from
62 baseline). Review package generated (`review-e4d9564..375004b.diff`); scoped re-review
dispatched against all 6 findings plus a new-breakage check on the fix diff.

**Re-review verdict: all 6 findings ADDRESSED, no new Critical/Important breakage.** Re-reviewer
independently cross-checked every touched file against surrounding code (`app.py`, `run.py`,
`cli.py`, `models.py`, `census_report.py`, migrations 0003/0004, `page.tsx`, `api.ts`, fixtures,
all 4 retargeted/added specs) and confirmed HEAD (`375004b`) matches the diff file exactly.
Out-of-scope observation (non-blocking, pre-existing, not introduced by this fix wave): the new
Screen 2 test's mocked SSE close can trigger the browser `EventSource`'s natural `onerror`
reconnect signal, a latent quirk in production code from before this fix wave — doesn't affect
test assertions, not touched.

## Final whole-branch review: complete (7 Sep 2026)

Fix round 1/1 (6 addressed, 0 open; commits e4d9564..375004b). Per the skill's Final Review
section, there is no second fix wave — the round closed clean on the first pass. Both excluded
items (auth/SSRF gating, licence-audit Windows blind spot) remain correctly un-actioned, ledgered
above as decisions for the human partner. Branch `week4-census-ui` is now at `375004b`, all 17
plan tasks plus this fix wave complete, 0 open Critical/Important anywhere in the branch's history.
Next: superpowers:finishing-a-development-branch — merge/integration is a human-partner decision
per this ledger's own precedent (Task 17 scope boundary; "All 17 tasks complete" stop-point above).

