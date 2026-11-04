# Open decisions — closed out

CLAUDE.md's "Before planning" gate: brief `01` §13 has 7 open decisions,
`00-SHARED-FOUNDATION.md` §12 has 7 more. Neither set was answered before
implementation started. This record closes all 14, dated 2026-09-14, after
most of Weeks 1–4 was already built — several answers are therefore
*ratifications* of what the code already does, not decisions made in
advance. That ordering problem is itself worth naming: brief `01`'s own
instruction was "bring me the list before designing," and that didn't
happen. Nothing found in the competitive inventory below forced a full
re-scope, but it did change the claimed differentiators — see
`docs/methodology.md` "Competitive claim verification" for the detail this
file only summarizes.

## Brief `01` §13 (Agent Perimeter)

**1. Competitive inventory (B8) — done, see `docs/methodology.md`.**
Positioning changes as a result: enterprise-deployment-posture (candidate a)
is dropped — Akto and Cisco already own that ground with more runtime depth
than a scanner offers. The data-path injection simulation (candidate b) is
kept as the lead differentiator — nothing found does this specifically.
Evidence-graded reporting (candidate c) is narrowed from "we publish
numbers" (several competitors already do, at much larger N) to
reproducibility/auditability — fixture corpus, golden SARIF, CI-regenerated
precision/recall table that fails the build on drift. This project should
not try to compete on census size against Trend Micro's 19,000-server sweep.

**2. Hosted scanner, or CLI + local UI only? — Ratified: CLI + local UI.**
Already built this way: `docker-compose.yml` runs db/api/web locally, no
multi-tenant hosting, no domain-verification-for-remote-targets logic
anywhere in `agent_perimeter/`. This was never written down as a deliberate
choice before now — worth noting since it forecloses the "hosted =
subscription story" path without that tradeoff having been weighed on paper.

**3. Injection simulation aggressiveness — Ratified: bring your own agent
(corrected 2026-11-04).** This entry previously read "bundled minimal agent
harness". That never matched the code: `agent_perimeter/checks/injection/agent_adapter.py`
bundles no agent and calls no model. It reads a transcript the client exports
from *their own* agent run against a server carrying the tracer marker
(`docs/byo-agent.md`; the instrumenting proxy it describes, the `instrument` command, was
implemented 2026-11-04, see `docs/superpowers/specs/2026-11-04-instrument-proxy-design.md`). The split is: Claim A (an injection path exists) is
proven by the scan itself, deterministically, with no agent
(`injection.path_proof`); Claim B (the client's agent acts on it) is measured
from the client's transcript. Rationale for BYO: no quota or model cost, cannot
fail on a demo when a free tier caps out, and it measures the agent actually
deployed rather than a proxy. Cost of BYO: Claim B needs a client willing to
run their agent through the `instrument` proxy. What the check shows depends
on the transcript. A canary transcript (written by the proxy, carrying a
per-run `AP-CANARY-<nonce>`) is causal: the check reports only when a later
call's arguments repeat a token the agent could have learned only from the
injected result — CRITICAL to a privileged-named tool, MEDIUM otherwise, LOW
when the whole injected sentence was copied verbatim (data pass-through, not
obedience). A legacy inert-marker transcript is correlation only: a
privileged-looking call after the marker is reported INFO and does not show
causation. Candidate (b) remains the lead differentiator, in this narrower
form.

**4. Disclosure embargo — Answered: 90 days.** `docs/security.md`: 90-day
embargo, aggregate-only publication and withheld digest/salt if a maintainer
never replies. No change.

**5. Registry scan scope: how many servers, selected how? — Decided:
full census of the official MCP Registry (Tier 1, full pagination — not a
sample), Tier 1 + Tier 2 (static artifact analysis) only for the first
publication. Tier 3 (live-discover, contacts real third-party servers)
stays unwired, per the existing 2026-09-09 human-partner decision recorded
in `docs/census/CHANGELOG.md`, until it clears code review.**

*Update, 2026-09-23 (human-partner ruling, supersedes the above).* Code
review found `probe_host()`/`run_tier3()` sent live probes with no
`ScopeFile` gate, conflicting with Never-rule 1, and the existing
per-target scope-file model does not fit a sample of unowned third-party
servers by construction — no redesign closes that gap without abandoning
either random sampling or per-target consent, and Never-rule 1 states no
carve-out mechanism. Ruling: **Tier 3 is dropped, not redesigned.**
`agent_perimeter/census/tier3.py` and its tests are deleted. See
`docs/census/CHANGELOG.md` "## Unreleased" (2026-09-23 entry) for the full
writeup. Rationale for the original Tier 1+2-only scope: a
"top-N by stars" or random-sample selection is exactly the kind of choice
the brief says to decide *before* collecting, and it also introduces a
selection-bias claim this project would then have to defend. Full-population
census of one authoritative registry is the more defensible claim and is
already what `agent_perimeter/census/sample.py`/`run.py` do end to end. Not
attempting to match Trend Micro's 19,000-server, multi-directory sweep — see
decision 1.

*Addendum, 2026-09-14 (human-partner decision).* Tier 1 remains a full
census. Tier 2 changed from top-N-by-downloads to a seeded uniform random
sample of up to n npm+PyPI packaged entries per ecosystem
(`census/sample.py`): ranking all 12,243 npm+PyPI entries via
pypistats.org / api.npmjs.org took hours and pypistats throttled most calls,
so the download-ranked frame was never actually attainable inside a
collection window. The seed is recorded on the `CensusRun` row and
published in the report and in `records.summary.json`. This trades the
popularity-weighted frame for an unbiased estimate of the ecosystem share
with a statable confidence interval (Wilson 95%, rendered next to each
share). The objection in the original text above was to *unrecorded*
selection — a choice made after seeing the data that a reader cannot
reproduce — and a published seed answers it: anyone can redraw the same
sample from the same population snapshot. Run #2 (2026-09-14) is
superseded for a second reason unrelated to sampling: its SDK-pin detector
took the first version token of a requirement, which for setuptools'
normalised `Requires-Dist: mcp<2.0.0,>=1.9.0` is the *cap*, so it recorded
"3.x" Python SDK pins that do not exist. The detector now records the lowest
lower bound and drops floor-gated source signals when there is no pin at
all; the method hash changed accordingly and run #3 carries the corrected
figures.

**6. Publish own false-positive rate? — Answered: yes.**
`docs/methodology.md`'s precision/recall table is live, CI-regenerated, and
non-optional per its own text ("If this table is stale, CI is broken"). No
change — this is now also the project's primary competitive claim (decision
1, candidate c), which raises the cost of that table ever going stale or
being caught overstating a number.

**7. Apache-2.0 or AGPL for this repo? — Answered: Apache-2.0.**
`LICENSE` present, confirmed in `docs/licences.md`. No change.

### Drift detection (15 Sep 2026)

Decided in `docs/superpowers/specs/2026-09-15-drift-detection-design.md` §2 (D1–D5): compare-on-scan, five drift fields, description text persisted, drift is a Finding, snapshot source is pluggable. One standing exception recorded: `GET /api/scans/{id}/drift` reads from the database. Task 9's "DB is audit-only" ruling still holds for findings/graph/SARIF; drift is history and the in-process cache cannot hold history across restarts.

## `00-SHARED-FOUNDATION.md` §12 (shared substrate)

**1. Publish `bok-core`/`bok-ui` packages, or vendor? — Decided: vendor
now (local shims), extract later.** `agent_perimeter/_contracts.py` and
`checks/descriptions/llm_judge.py`'s `JudgeGateway` are explicit,
documented stand-ins ("Local stand-ins for `bok-core` interfaces... Swap to
`from bok_core.gateway import ...` then"); `web/src/lib/_bok-ui.tsx` is the
same pattern on the frontend. This was already the de facto engineering
choice, made under time pressure rather than decided up front. Ratified
rather than reversed: extracting a real `bok-core` package now, with only
one consumer, would be premature — the shims are honestly labeled and the
`Claim`/`Finding` contracts they mirror are stable. Revisit when a second
project (`ledger-sense`, `selector-drift`, or `ground-truth`) actually needs
the same primitives — that's the point at which a shared package earns its
release-step overhead.

**2. `bok-cli` (unified) or four independent CLIs? — Deferred, not
decided.** Moot with only one of four projects built. Decide when project
two starts; premature to commit either way with a sample size of one.

**3. Which model-provider accounts do you actually have? — Decided
2026-09-14: free-tier only, no paid provider account provisioned.**
`checks/descriptions/llm_judge` — the only checker gated on a model, per
CLAUDE.md's determinism budget — runs in its degraded/disabled lane by
default. This is a valid, tested configuration (the ≥90%
`test_degraded_mode_still_produces_findings` floor exists for exactly this
case), not a fallback of last resort, and it keeps R4 ($0 recurring cost)
intact. Revisit if/when a provider account is provisioned; update
`docs/methodology.md`'s provider-inventory table at that point, not before —
don't guess at terms for an account that doesn't exist.

**4. Supabase acceptable, or compose-only self-hosted? — Ratified:
compose-only self-hosted.** `docker-compose.yml` runs `postgres:16-alpine`
directly; no Supabase (or any third-party data processor) reference
anywhere in the codebase. This was already the built answer, now written
down. More defensible for a security-tool sales conversation, per the
brief's own framing, at the cost of more ops work than a managed Postgres.

**5. Public from commit one, or public at first release? — Answered
2026-09-14: public from commit one.** `github.com/Berakhah/agent-perimeter`
is already public (confirmed by the user directly; unauthenticated API
checks were rate-limited and inconclusive on their own). This is a
retroactive ratification, not a decision made before the first push — the
repo was already public before this question was asked. Implication: the
64 unpushed local commits (see status note below) are not yet visible
externally, but everything already on `origin/main` has been public the
whole time, including any commit message or code comment that assumed
otherwise.

**6. Apache-2.0 for everything, or AGPL for the scanner? — Answered:
Apache-2.0.** Same evidence as brief `01` §13.7. No change; consistent
across both documents.

**7. How much time per week is actually available? — Answered
2026-09-14: 10–15 hrs/week (part-time).** Plan remaining work — publishing
the census, a genuine clean-machine verification (done 2026-09-15 on a
fresh GitHub-hosted VM — `docs/evidence/clean-machine.md`), syncing 64 unpushed
commits and watching CI go green on the full codebase for the first time —
as spread over roughly 2–3 real weeks, not calendar days. Do not assume a
full-time pace when sequencing what comes next.

## Standing status note (not one of the 14)

*Addendum, 2026-09-16.* The local/origin sync (getting `main` and
`origin/main` aligned, `gh auth login`, and `.github/workflows/ci.yml`
running on every push) happened on 2026-09-14/15, and CI has been green on
every push since. "CI is green" is now usable evidence; this no longer
blocks acting on any of the 14.

## Addendum — GitHub Action delivery (2026-09-16)

The drift spec (`docs/superpowers/specs/2026-09-15-drift-detection-design.md`
§10) deferred a GitHub Action pending a publishing decision. Decided, with
the reasoning in `2026-09-16-github-action-design.md` D3/D8:

- **Delivery: install from this repo at the action's own ref.** `action.yml`
  at the root; `uses: Berakhah/agent-perimeter@v1` installs `agent_perimeter`
  from the action's checkout. No PyPI release, no GHCR image — both would add
  a recurring publishing surface for a package that has never been released,
  and neither is needed for the action to work.
- **Marketplace: not listed.** `branding` is in place so a listing is one
  click; listing implies support expectations that are a human-partner call.
- **Versioning:** `v1.0.0` release + floating `v1` tag moved by
  `.github/workflows/release.yml`.

## Addendum — tracked follow-ups from the instrument-proxy review (2026-11-04)

Recorded, not done. Neither is fixed on the `instrument-proxy` branch; the
graph-sink change was ruled out of that wave on purpose.

- **FU-1. `injection.agent_adapter` severity should come from graph-derived
  sinks, not only `_is_privileged`.** Today severity keys off name tokens
  (`run`, `exec`, `write`, `delete`, `send`, `post`, `upload`). A canary
  repeated into `sync_to_webhook` — an exfiltration sink by any reading, and
  the sink `injection.path_proof` itself reports — rates MEDIUM because no
  token matches. Fix: rate CRITICAL when the receiving tool is a sink in the
  capability graph (`find_paths` over the scanned listing), keeping the name
  heuristic as the fallback when no listing is available.
  **Resolved 2026-11-04.** The receiving tool rates CRITICAL when it is a
  backed sink in the capability graph or passes `_is_privileged`; otherwise
  MEDIUM. A sink is backed when its privileged-capability edge on the
  source->sink path is schema-, name- or probe-derived; a sink resting only on
  description prose (for example a net_out edge at confidence 0.4) stays
  MEDIUM and the finding names it as a possible sink. The proxy records backed
  sinks under `canary.sinks` and description-only ones under
  `canary.weak_sinks`, refreshed on every tools/list page. A transcript with a
  `sinks` list is judged on it plus the name heuristic; only an older
  transcript without one falls back to `find_paths` over the scanned listing,
  so a listing from another target cannot upgrade a transcript. The title says
  which reason applied. Only firing is measured, so the corpus counts in
  `docs/methodology.md` did not move.
  **Final-review follow-up (2026-11-04).** The recorded sinks are now a
  session-wide union that never shrinks (with `canary.sink_derivations`), and
  each recorded call carries the receiving tool's classification at call
  time (`"sink": {"strength", "derivation"}`), so an agent re-listing page 1
  after the bait cannot turn a CRITICAL into a MEDIUM. The adapter prefers
  the bait call's own classification, then the session union, then (only for
  transcripts with neither) the scanned listing. The CRITICAL reason names
  the backing edge's derivation, e.g. "a sink in the capability graph
  (name-derived)". The methodology regeneration showed no diff.
- **FU-2. `agent_perimeter/discover/enumerate.py` ignores `nextCursor`.**
  Discovery reads only the first `tools/list` page, so every check that
  consumes the enumerated listing misses tools on later pages: a
  project-wide false negative on paginated servers. The instrument proxy
  already follows cursors (with repeat-cursor loop protection) and is the
  model for the fix.
  **Resolved 2026-11-04.** `enumerate_tools` now follows `nextCursor`; a later
  page's entry for a name seen on an earlier page replaces it, first-seen
  order kept; duplicate names within one page are all kept, as drift keys on
  them.
  Paging stops on an absent or non-string cursor, or early on a repeated
  cursor, `MAX_TOOL_PAGES` (100), or a `TransportError` on a later page (the
  earlier pages' tools are kept). All three early stops log a warning and add
  a scan note, rendered in the HTML report, the CLI summary, the API status
  body, the SSE terminal frame, SARIF `toolExecutionNotifications` and the
  web live-scan screen. A `TransportError` on page 1 still yields no tools.
  The proxy's `_page_through` shares the same cap, so a hostile upstream
  cannot keep it paging under its lock.
  **Final-review follow-up (2026-11-04).** An incomplete listing no longer
  feeds drift: `drift.description_drift` is skipped as
  `listing_incomplete`, the scan is persisted with `scan.listing_complete =
  false` (migration 0008, existing rows true) and is never selected, or
  accepted when pinned, as a baseline. The CLI refuses `--snapshot` for it
  (exit 2, file not written), `--fail-on-drift` fails closed (exit 2) when it
  could not compare, and `drift scan:<id>` refuses an incomplete operand. The
  proxy's `_page_through` now mirrors `enumerate_tools`: a failed later page
  keeps the earlier pages and clears the pending cursor, so later
  `tools/call`s still reach the upstream. Every early stop is recorded as a
  fixed-vocabulary `canary.listing_incomplete`; `injection.agent_adapter`
  names it in the finding caveat, unions in the scanned listing's sinks, and
  adds a scan note (`ScanContext.notes`) whether or not there is a finding.
  The proxy also merges pages with discovery's `merge_page`, so same-page
  duplicate names are kept for source detection there too. The eval harness
  raises `IncompleteFixtureListing` instead of scoring a fixture whose
  listing stopped early.
  **Residual-review follow-up (2026-11-04).** A page-1 failure is now an
  incomplete listing too, not an empty one: a `TransportError` on page 1, or
  a page-1 reply with no `tools` list, adds a scan note and sets
  `listing_complete = false`, so drift is skipped, the scan is never a
  baseline and `--snapshot` refuses it (exit 2). The scan itself still runs.
  Only a successful reply carrying `"tools": []` is a complete, empty
  listing. A later page with no `tools` list stops paging the same way.
