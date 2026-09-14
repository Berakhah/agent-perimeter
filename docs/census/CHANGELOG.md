# Census changelog

Results are versioned, never overwritten. Each real run gets its own dated
directory (`docs/census/<date>/`), carrying `records.csv`,
`records.summary.json`, and the rendered report for that run. A correction is
a new dated entry, never an edit to an old one.

## Unreleased

Nothing pending. The first published run is the dated entry below
(`## 2026-09-14`). Tier 3 (the live-discover stratum,
`agent_perimeter/census/tier3.py`) remains deliberately unwired — a
human-partner decision (2026-09-09, ratified in `docs/open-decisions.md`
decision 5): it makes real contact with third-party servers and has not been
through code review. It remains a self-contained, tested module with no
integration into `run_census`. Every published report's live-discover section
reads "not yet run", per the report's own empty-state copy.

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

- **Population:** 31,939 registry entries observed, full pagination (320
  pages of 100, 0 pagination failures). Distribution: 17,887 `remote_only`,
  8,591 `package_npm`, 3,652 `package_pypi`, 1,353 `package_other`, 456
  `none`. 56% of the population is remote-only and carries no fetchable
  artifact; Tier 2 says nothing about those entries.
- **Tier 2 (static artifact analysis):** a **seeded uniform random sample**
  of up to 200 packaged entries per ecosystem — not a download ranking.
  Sample seed 4188178442 (recorded in `records.summary.json`, printed by the
  run). 200 npm + 200 PyPI entries selected; artifacts fetched OK for npm
  n = 196 and PyPI n = 191. Never pooled for the headline figure.
  - Classification (from `records.summary.json`): npm — 3 supports, 173
    does_not_support, 20 unknown; n = 176 classified, share 1.7%. PyPI — 0
    supports, 140 does_not_support, 51 unknown; n = 140 classified, share
    0.0%. Pooled, for reference only — 3 supports, 313 does_not_support, 71
    unknown; n = 316, share 0.9%.
  - Every one of the 71 `unknown` records carries the same caveat: no SDK pin
    and no parseable source in the published artifact.
  - SDK pin presence among examined artifacts: npm 173 pinned / 23 no pin;
    PyPI 138 pinned / 53 no pin. Pinned SDK major: npm 0.x 3, 1.x 163,
    2.x 7; PyPI 0.x 1, 1.x 119, 2.x 17, 3.x 1.
- **Tier 3 (live-discover):** did not run. See Unreleased.
- **Collection window:** 2026-09-14 20:34:16 UTC to 2026-09-14 21:01:33 UTC
  (27 minutes).
- **Tool version:** 0.1.0. **Method hash:** `449edc04f9c3decc`.
- **Fetch failures:** 13 (0 registry pagination, 13 artifact fetch), excluded
  from every *n* and stated as part of the sample. By ecosystem — npm: 196
  ok, 2 not_found, 1 parse_error, 1 too_large; PyPI: 191 ok, 8 not_found,
  1 parse_error. By cause: 8 "no downloadable artifact" (7 PyPI, 1 npm),
  2 "package not found" (1 each), 2 "archive rejected: member exceeds 32 MiB
  size cap" (1 each), 1 npm "declared size exceeds 32 MiB".
- **Files:** `census.html` (report), `records.csv` (one row per record,
  salted-digest keyed, no names or URLs), `records.summary.json` (the
  report's figures). `uv run python analysis/census_analysis.py
  docs/census/2026-09-14/records.csv` reproduces every figure and reports
  `match` on every line as of this entry.
- **Discarded run, for the record:** an earlier full run the same day
  (2026-09-14 19:51–20:24 UTC) used an SDK-pin detector that only looked at
  the archive root and so classified 94% of examined artifacts `unknown`. It
  was discarded and never published. The detector was fixed to look under
  `package/`, `<name>-<version>/`, `PKG-INFO` and `*.dist-info/METADATA`
  (commit `b573c0e`), and the run above was made with the fixed code.
- **Method changes landed during this plan** (all before the run above):
  Tier 2 moved from a download-count ranking to the seeded random sample
  described here; a transient registry page failure now aborts the run
  (`PaginationTruncated`) instead of silently truncating the population.
- **Limitations carried forward from `docs/methodology.md`, plus what the
  sceptic's read found:**
  - The sample estimates the share among *packaged* registry entries only;
    the 56% remote-only majority is unexamined by construction.
  - "supports 2026-07-28" is a statement about a published artifact —
    SDK version floor plus static feature detection — not about any
    deployment's observed behaviour.
  - **Two-signals rule under-count:** 24 sampled artifacts (7 npm, 17 PyPI)
    pin a 2.x SDK but expose no `server/discover` handler string in shipped
    source, so under the two-signals rule (pin AND source signal) they count
    as `does_not_support`. If the SDK serves `server/discover` on the
    package's behalf, each is a false does-not-support; the census cannot
    tell from the artifact alone. This is a detection limitation, not a
    finding about those packages, and it biases the reported share
    downward.
  - The 13 fetch failures are excluded from *n* and listed above; the 71
    `unknown` records are excluded from the share's denominator.

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
