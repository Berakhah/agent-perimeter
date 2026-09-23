# Census changelog

Results are versioned, never overwritten. Each real run gets its own dated
directory (`docs/census/<date>/`), carrying `records.csv`,
`records.summary.json`, and the rendered report for that run. A correction is
a new dated entry, never an edit to an old one.

## Unreleased

**2026-09-23 — Tier 3 (live-discover stratum) dropped permanently,
human-partner ruling, superseding the 2026-09-09 "pending code review"
gate.** Code review of `agent_perimeter/census/tier3.py` found
`probe_host()`/`run_tier3()` sent a live, unauthenticated `server/discover`
JSON-RPC probe to each sampled host with no `ScopeFile` gate — every other
active-probe path in the codebase (`checks/registry.py`, `scan_runner.py`,
`checks/active/base.py`) calls `require_scope(scope, target=...)` first;
tier3.py did not. That is a direct conflict with CLAUDE.md Never-rule 1
("No active probe without a scope file... Fails closed"), and not a
one-line fix: `ScopeFile`/`require_scope` model one authorising party
consenting to one named `target`, and Tier 3's whole design was a seeded
random sample of ~100 *unowned, unrelated* third-party servers drawn from
the public registry — there is no single party who could sign a scope file
covering an arbitrary sample of servers the project has no relationship
with. Redesigning around this would mean abandoning either random sampling
(defeating the population-representativeness claim) or per-target consent
(defeating the rule); Never-rule 1 is written unconditionally, with no
stated carve-out mechanism, and Tier 3 was already the one deliberate
tension against Never-rule 2 (passive-only) before this review even
started. Ruling: dropped, not redesigned. `agent_perimeter/census/tier3.py`
and `tests/census/test_tier3.py` are deleted; the report's live-discover
section is generic infrastructure that stays (in case a future,
differently-authorised design ever populates it) but its empty-state copy
now says "not run" rather than "not yet run" — this stratum is not merely
unwired, it has no implementation and no path to one that clears Never-rule
1 in its current form. See `docs/open-decisions.md` decision 5 for the
cross-reference.

Nothing else pending. The first published run is the dated entry below
(`## 2026-09-14`), Tier 1 + Tier 2 only — unaffected by the above, since
Tier 3 was never wired into `run_census` or any published report.

Historical note: `agent_perimeter.census.detect.SDK_FLOOR` was marked
placeholder/unverified until **2026-09-09**, when it was verified against the
real `python-sdk`/`typescript-sdk` release history — see
`docs/methodology.md` "## SDK version floors". Verification also surfaced a
real detection bug, fixed before any run: `@modelcontextprotocol/sdk` (v1)
never shipped a 2.x release, so `detect.py` could never have matched a v2 npm
artifact's SDK pin at all. `_JS_SDK_NAMES` now also recognises
`@modelcontextprotocol/server`/`/core`, the real v2 package names.

## 2026-09-14

First publication. Full census of the official MCP Registry
(`https://registry.modelcontextprotocol.io/v0/servers`), Tier 1 + Tier 2.
This is the third full run of the day; the first two are recorded below as
discarded/superseded and were never published.

- **Population:** 31,953 registry entries observed, full pagination (320
  pages of 100, 0 pagination failures). Distribution: 17,897 `remote_only`,
  8,593 `package_npm`, 3,653 `package_pypi`, 1,354 `package_other`, 456
  `none`. Eligible Tier 2 frame (npm + PyPI packaged entries): 12,246. 56%
  of the population is remote-only and carries no fetchable artifact; Tier 2
  says nothing about those entries.
- **Tier 2 (static artifact analysis):** a **seeded uniform random sample**
  of up to 200 packaged entries per ecosystem — not a download ranking.
  Sample seed 2307759973 (recorded in `records.summary.json`, printed by the
  run). 200 npm + 200 PyPI entries selected; artifacts fetched OK for npm
  n = 195 and PyPI n = 182 (pooled 377).
  - **Headline, per ecosystem, with a Wilson score 95% interval:** npm —
    0 of 174 classified artifacts show published-artifact evidence of
    support for 2026-07-28, share 0.0% (95% CI 0.0–2.2%); 21 unknown. PyPI —
    0 of 128, share 0.0% (95% CI 0.0–2.9%); 54 unknown. Pooled across both
    ecosystems, for reference only — 0 of 302, share 0.0% (95% CI
    0.0–1.3%); 75 unknown. The report's headline states the two
    per-ecosystem figures first and the pooled figure second, labelled as
    pooled for reference; the intervals are why a 0 count is not reported
    as "none": 0/174 is consistent with a true share of up to about 2.2%.
  - Classification (from `records.summary.json`): npm — 0 supports, 174
    does_not_support, 21 unknown, n = 174. PyPI — 0 supports, 128
    does_not_support, 54 unknown, n = 128. Pooled — 0 / 302 / 75, n = 302.
  - Of the 75 `unknown` records, 74 carry no SDK pin and no parseable
    source; 1 (PyPI) carries a source signal but no SDK pin, and under the
    rule from commit `970e134` an unpinned artifact is unknown outright —
    the pin is the gate, so a source signal alone never classifies.
  - SDK pin presence among examined artifacts: npm 174 pinned / 21 no pin;
    PyPI 128 pinned / 54 no pin. Pinned SDK major: npm 0.x 3, 1.x 166,
    2.x 5; PyPI 0.x 2, 1.x 113, 2.x 13. No 3.x pin exists — the "3.x pin"
    the superseded run #2 reported was a `<3` upper-bound cap misread as a
    pin (see below).
- **Tier 3 (live-discover):** did not run. See Unreleased.
- **Collection window:** 2026-09-14 21:48:01 UTC to 2026-09-14 22:10:48 UTC
  (23 minutes).
- **Tool version:** 0.1.0. **Method hash:** `1c49920d8849ff45`.
- **Fetch failures:** 23 (0 registry pagination, 23 artifact fetch), excluded
  from every *n* and stated as part of the sample. By ecosystem — npm: 195
  ok, 4 not_found, 1 too_large; PyPI: 182 ok, 17 not_found, 1 too_large. By
  cause: 16 "no downloadable artifact", 5 "package not found", 2 "declared
  size exceeds the archive cap".
- **Files:** `census.html` (report), `records.csv` (one row per record,
  salted-digest keyed, no names or URLs), `records.summary.json` (the
  report's figures, including the population distribution, fetch-failure
  split, detection limitations and `wilson95` arrays). `uv run python
  analysis/census_analysis.py docs/census/2026-09-14/records.csv`
  reproduces every figure and reports `match` on every line as of this
  entry.
- **Discarded run #1, for the record:** an earlier full run the same day
  (2026-09-14 19:51:19–20:24:25 UTC) used an SDK-pin detector that only
  looked at the archive root and so classified 94% of examined artifacts
  `unknown`. It was discarded and never published. The detector was fixed
  to look under `package/`, `<name>-<version>/`, `PKG-INFO` and
  `*.dist-info/METADATA` (commit `b573c0e`).
- **Superseded run #2, for the record:** a second full run
  (2026-09-14 20:34:16–21:01:33 UTC, seed 4188178442, method hash
  `449edc04f9c3decc`) was rendered and reviewed but never published. Its
  pin detector took the first version token of a specifier, so a
  `Requires-Dist` line normalised to `<2` or `<3` (PKG-INFO / METADATA put
  upper bounds first) was read as a pin at that cap — the source of a
  phantom "3.x pin" — and an unpinned artifact carrying a handler string
  could still be classified. Both were fixed (commits `3477cfa`, `970e134`:
  the pin is the lowest lower bound of the specifier; an unpinned artifact
  is unknown outright; Wilson intervals added), and the run above was made
  with the fixed code and a fresh seed. Run #2 reported 3 npm `supports`;
  those three were genuine (pinned 2.0.0 with a handler string), but run #3's
  seed drew a different sample of the same frame and found 0. That is
  exactly why the Wilson interval is published: 0/174 and 3/176 are both
  consistent with a true share in the low single digits of a percent.
- **Method changes landed during this plan** (all before the run above):
  Tier 2 moved from a download-count ranking to the seeded random sample
  described here; a transient registry page failure now aborts the run
  (`PaginationTruncated`) instead of silently truncating the population;
  the report leads per-ecosystem with the pooled figure labelled for
  reference; `unknown` means fetched and extracted but no SDK pin; shares
  carry a Wilson 95% interval and render to one decimal; the page and the
  summary carry the population distribution, the fetch-failure split and
  per-cause breakdown, the eligible-frame scope statement and the
  detection limitations below.
- **Limitations carried forward from `docs/methodology.md`, plus what the
  sceptic's read found:**
  - The sample estimates the share among *packaged* npm/PyPI registry
    entries only (the 12,246-entry eligible frame); the 56% remote-only
    majority and the 1,354 `package_other` entries are unexamined by
    construction.
  - "supports 2026-07-28" is a statement about a published artifact —
    SDK version floor plus static feature detection — not about any
    deployment's observed behaviour.
  - **Two-signals rule under-count, pin without handler:** 18 examined
    artifacts (5 npm, 13 PyPI) pin an SDK at or above the `server/discover`
    floor (2.0.0) but expose no `server/discover` handler string in shipped
    source, so under the two-signals rule (pin AND source signal) they count
    as `does_not_support`. If the SDK serves `server/discover` on the
    package's behalf, each is a false does-not-support; the census cannot
    tell from the artifact alone. This is a detection limitation, not a
    finding about those packages, and it biases the reported share
    downward. Stated in the report and in `records.summary.json` under
    `limitations`.
  - **Two-signals rule under-count, floor-dropped source signal:** 11
    examined artifacts (8 npm, 3 PyPI) mention a 2026-07-28 feature in
    shipped source but pin a pre-2.0 SDK; the pin wins and they count as
    `does_not_support` (detect.py's caveat "source mentions … but the sdk
    pin predates it"). Also stated in the report and the summary.
  - **Unpinned with a source signal:** 1 examined artifact (PyPI) carries a
    source signal but no SDK pin and is `unknown`, never `supports`.
  - The 23 fetch failures are excluded from *n* and listed above; the 75
    `unknown` records are excluded from the share's denominator. An
    unfetchable artifact is a fetch failure, never an `unknown`.

Every future entry here states, at minimum:

- Population: registry entries observed, and Tier 2's *n* **per ecosystem**
  — npm and PyPI counted separately, never pooled into one figure (the
  report's own artifact-stratum table explains why: the registry's real
  ecosystem split makes a single pooled *n* misstate what was actually
  sampled from each).
- Whether the live-discover (Tier 3) stratum ran that day, and its sample
  size — or, just as plainly, that it did not run, exactly as the report
  itself states when the stratum is empty.
- Tool version and method hash, so a changed collection method cannot
  silently reuse an old report's label.
- Fetch failures, and every other known limitation carried forward from
  `docs/methodology.md`.
