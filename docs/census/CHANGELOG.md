# Census changelog

Results are versioned, never overwritten. Each real run gets its own dated
directory (`docs/census/<date>/`), carrying `records.csv`,
`records.summary.json`, and the rendered report for that run. A correction is
a new dated entry, never an edit to an old one.

## Unreleased

No census has been published yet. `agent_perimeter.report.census_report`
(`render_census`, `export_raw`) and `agent_perimeter.census.run.run_census`
exist and are tested — see `tests/report/` and `tests/census/` — but no real
run has been executed against the live registry and published under a dated
directory below.

One thing blocked a real publication as of the last entry above; it is now
resolved, and one is deliberately deferred:

- ~~`agent_perimeter.census.detect.SDK_FLOOR` is explicitly marked
  placeholder/unverified~~ **Resolved 2026-09-09.** Verified against the
  real `python-sdk`/`typescript-sdk` release history — see
  `docs/methodology.md` "## SDK version floors". Verification also surfaced
  a real detection bug, now fixed: `@modelcontextprotocol/sdk` (v1) never
  shipped a 2.x release, so `detect.py` could never have matched a v2 npm
  artifact's SDK pin at all. `_JS_SDK_NAMES` now also recognises
  `@modelcontextprotocol/server`/`/core`, the real v2 package names.
- Tier 3 (the live-discover stratum, `agent_perimeter/census/tier3.py`) is
  **deliberately left unwired for the first publication** — a human-partner
  decision (2026-09-09): publish v1 with Tier 1 (registry pagination) + Tier
  2 (static artifact analysis) only, since Tier 3 makes real contact with
  third-party servers and hasn't been through code review yet. It remains a
  self-contained, tested module with no integration into `run_census`. Any
  published report's live-discover section honestly reads "not yet run", per
  the report's own empty-state copy.

When the first real run publishes, its entry here states, at minimum:

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
