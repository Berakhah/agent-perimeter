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

**3. Injection simulation aggressiveness — Ratified: bundled minimal agent
harness.** `agent_perimeter/checks/injection/agent_adapter.py` is a shipped
adapter, not a "bring your own agent" requirement. Consistent with keeping
candidate (b) as the lead differentiator — a harness that requires the
client to already have a working agent integration would gate the exact
capability being sold.

**4. Disclosure embargo — Answered: 90 days.** `docs/security.md`: 90-day
embargo, aggregate-only publication and withheld digest/salt if a maintainer
never replies. No change.

**5. Registry scan scope: how many servers, selected how? — Decided:
full census of the official MCP Registry (Tier 1, full pagination — not a
sample), Tier 1 + Tier 2 (static artifact analysis) only for the first
publication. Tier 3 (live-discover, contacts real third-party servers)
stays unwired, per the existing 2026-09-09 human-partner decision recorded
in `docs/census/CHANGELOG.md`, until it clears code review.** Rationale: a
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
the census, a genuine clean-machine verification, syncing 64 unpushed
commits and watching CI go green on the full codebase for the first time —
as spread over roughly 2–3 real weeks, not calendar days. Do not assume a
full-time pace when sequencing what comes next.

## Standing status note (not one of the 14, but blocks acting on several
of them)

Local `main` was 64 commits ahead of `origin/main` as of 2026-09-14 (last
pushed commit `5418be3`), and `gh auth login` has not been run. Decision 5
above (public from commit one) is already true for what's pushed, but nearly
half the project's history — the capability graph, the web UI, the a11y
suite, the full census pipeline, the containment tests — has never been
validated by `.github/workflows/ci.yml`. Syncing this is a prerequisite for
trusting "CI is green" as evidence for anything in this file or in
`docs/methodology.md`'s DoD table, and needs an explicit go-ahead before
pushing (see conversation record — this is a visible, external action, not
a local edit).
