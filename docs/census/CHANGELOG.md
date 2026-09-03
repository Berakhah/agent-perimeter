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

Two things block a real publication, independent of this task:

- `agent_perimeter.census.detect.SDK_FLOOR` is explicitly marked
  placeholder/unverified (`docs/methodology.md` — "## SDK version floors").
  Every artifact-stratum number this report states moves if those floors are
  wrong; they must be checked against the real SDK changelogs first.
- Tier 3 (the live-discover stratum, `agent_perimeter/census/tier3.py`) is
  not wired into `run_census` yet — it is a self-contained, tested module
  with no integration that populates a real `CensusRecord` from it. Until
  that lands, any published report's live-discover section will honestly
  read "not yet run", per the report's own empty-state copy.

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
