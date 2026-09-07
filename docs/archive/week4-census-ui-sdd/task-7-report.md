# Task 7 report: the published census report

## Fix round 1 (review of commit 89b56a5): 3 Important findings, all fixed

Commit: `5cd18c8` — "fix: close 3 review findings on the census report
(commit 89b56a5)"

### Finding 1 — embedded CSS was HTML-escaped, breaking print-mode rules

`census.html.j2` had `<style>{{ css }}</style>` with no `|safe`, and
`render_census`'s `Environment` autoescapes `.j2`/`.html` filenames. Every
`"` in `report.css` was rendered as `&#34;` — invalid inside a `<style>`
block, and specifically broke `font-family: "IBM Plex Mono", ...` and the
print-mode `content: attr(data-glyph) " ";` / `content: " (" attr(href)
")";` rules, which are the no-colour-only-encoding mechanism this task was
required to reuse verbatim from Week 3.

**Fix:** `<style>{{ css|safe }}</style>` — `css` is a static, project-
authored stylesheet string (never record-derived), so this is safe.
**Test added:** `test_embedded_stylesheet_is_not_html_escaped` — asserts
`'"IBM Plex Mono"'` (with real quote characters) appears verbatim, and that
neither `&#34;` nor `&quot;` appears anywhere inside the rendered
`<style>...</style>` block.

### Finding 2 — the live-discover "Share" figure was an unguarded, misleading 100%

`does_not_support` is structurally always 0 for the probe stratum (a single
`server/discover` call can confirm support, never its absence), so
`Aggregate.share = supports/n` always evaluated to 100% whenever there was
at least one success — regardless of how many hosts never answered at all.
2 supports + 5 unreachable rendered "Share: 100%" in the same row as
"Unknown: 5", with no caveat on that specific figure.

**Fix:** removed the "Share" column/cell from the live-discover table
entirely (option (a) from the finding — a percentage of a denominator this
stratum structurally can't populate is inherently misleading, not just
under-captioned) and replaced it with an explicit sentence stating the raw
non-response count: "*N* of the *n* sampled hosts never answered a request,
or were excluded before one was sent: that non-response count is the number
that matters here, not a derived percentage." **Test added:**
`test_probe_stratum_never_renders_a_bare_percentage` — builds a 2-supports/
5-unknown fixture, slices out just the "Live-discover stratum" section of
the rendered HTML, and asserts no `%` character appears in it at all (plus
that the raw 5/7 counts and "non-response" wording are present).

One self-correction caught while writing this test: my first draft of the
caption literally contained the substring `"100%"` in its own explanatory
prose ("...would make any supports-over-n figure read as 100%..."), which
trivially broke a naive `"100%" not in html` assertion — not a test bug, a
copy bug (the caption itself must never state the number it's warning
against). Reworded to "would look fully positive" instead, with no digits.
I also learned the first version of the assertion was too broad in the
other direction: `"100%" not in html` was failing anyway because
`report.css` legitimately contains `width: 100%` on an unrelated `table`
rule. Fixed by scoping the assertion to just the live-discover section's
HTML slice rather than the whole page.

### Finding 3 — `census_analysis.py` required a sidecar the completion gate doesn't ask for

The Week 4 completion gate's literal wording is "reproduces every published
figure from the published CSV alone." My first version hard-required
`records.summary.json` and exited with an error if it was absent, which
doesn't satisfy that wording — `records.csv` (with the `stratum` column I
added) already carries everything needed to recompute every per-stratum,
per-ecosystem figure by grouping and counting.

**Fix:** restructured `check()`/`main()` so the sidecar is optional:
`_figures()` now flattens the recomputed data into one ordered list of
`(label, value)` pairs that both code paths share (so they can never drift
apart from each other) — with a sidecar present, each figure is compared
against it and mismatches print `MISMATCH`; without one, each figure is
simply printed for a human to compare against the report by eye, and the
script always exits 0 in that mode (there is nothing to fail against). Only
a genuine published-vs-recomputed disagreement, when a sidecar *is*
present, returns failure. **Tests added** (`tests/report/test_census_analysis.py`,
loaded from its file path via `importlib` since it's a loose top-level
script outside the `agent_perimeter` package by design — see that module's
own docstring on why it must stay import-free of the package it's
verifying):
- `test_check_succeeds_from_the_csv_alone_with_no_summary_sidecar` — deletes
  the sidecar `export_raw` wrote and confirms `check()` still returns `True`.
- `test_main_exits_zero_from_the_csv_alone` — same, through the `main()`
  CLI entry point, asserting exit code 0 and that recomputed figures are
  printed.
- `test_check_matches_the_summary_sidecar_when_present` — the happy path
  with both files present.
- `test_check_reports_a_real_mismatch_instead_of_papering_over_it` —
  corrupts one figure in the sidecar and confirms `check()` returns `False`
  (the failure mode still works; making the sidecar optional didn't make
  the tool toothless when one is present).

### The "pooled (both ecosystems)" row — reviewer's judgment call, confirmed

I agree with the reviewer's reading. The plan's "never pooled" language
targets (a) the artifact stratum vs. the live-discover stratum — genuinely
different populations and methods, never combined into one percentage — and
(b) Task 5's correction that the tier-2 *selection* metric (download counts)
is not comparable across npm/PyPI, so a single unlabelled sample size would
misstate what was drawn from each ecosystem. Neither concern applies to a
pooled *support-rate* figure: whether a package's source implements
`server/discover` is not an ecosystem-relative measurement the way a raw
download count is, so summing supports/does-not-support/unknown across
npm+PyPI for one extra summary row is a legitimate aggregate, not a
disguised version of either banned pooling. The per-ecosystem rows are
always rendered first and are never omitted, and the pooled row's "Tier-2
target n" column correctly shows "—" rather than implying a single pooled
sample size exists. No change made.

### Verification (fix round 1)

- `uv run pytest tests/report/` — 45 passed.
- `uv run pytest tests/report/test_census_analysis.py -v` — 4 passed
  (new file).
- `uv run ruff check .` — all checks passed.
- `uv run mypy --strict agent_perimeter` — success, 90 source files.
- `uv run mypy --strict tests/report/test_census_analysis.py
  tests/report/test_census_report.py analysis/census_analysis.py` —
  success, 3 source files (beyond the gate's own required command, same
  practice as fix round 0).
- Full suite: `uv run pytest -q` — **598 passed**, coverage 93.72%
  (`--cov-fail-under=75` met).

## Original implementation (commit 89b56a5)

## What was implemented

- `agent_perimeter/report/census_report.py` — `TERM_DEFINITIONS`, `Aggregate`
  (`supports`/`does_not_support`/`unknown`, `n` and `share` as derived
  properties), `aggregate(records) -> dict[str, Aggregate]`,
  `render_census(run, records) -> str`, `export_raw(run, records, *, salt,
  out) -> Path`.
- `agent_perimeter/report/templates/census.html.j2` — reuses Week 3's
  `report.css` verbatim (no new stylesheet), renders both strata as
  separate, individually-labelled sections plus term definitions,
  tool-version/method-hash, and links to the raw data, the analysis script,
  the disclosure policy, and the changelog.
- `analysis/census_analysis.py` — standalone, stdlib-only script that
  recomputes every published figure straight from `records.csv` and checks
  it against a `records.summary.json` sidecar (see design decision below),
  printing `match`/`MISMATCH` per line.
- `docs/census/CHANGELOG.md` — documents that no real census has been
  published yet (Tier 3 isn't wired into `run_census`, and `SDK_FLOOR` is
  still an unverified placeholder), and states what a real entry must
  include when one lands.
- `tests/report/factories.py` — `census_fixture()`, builds in-memory
  `CensusRun`/`CensusRecord` objects (no DB session needed) for both strata.
- `tests/report/test_census_report.py` — 19 tests: the brief's original 7
  (adapted) plus 12 covering the two-stratum design.

## Two-stratum design decision

`aggregate(records) -> dict[str, Aggregate]` keeps the brief's exact given
signature — it classifies whatever homogeneous list it's handed by reading
each record's `feature_set_json["derivation"]` (`"artifact"` or `"probe"`)
and applying that stratum's rule; records with neither tag are skipped, never
miscounted as `does_not_support`. `render_census` and `export_raw` do the
stratum- (and, for artifact, per-ecosystem) partitioning *before* calling
`aggregate()`, so the two strata's `Aggregate`s are always separate objects
that are never added together — verified structurally (no expression in
either `census_report.py` or the template ever combines
`artifact_agg`/`probe_agg`) and by
`test_two_strata_render_as_separate_never_pooled_sections`.

Per-record classification rules, and why:
- **Artifact stratum**: `is_unknown` → `unknown`; else `"server_discover" in
  features` → `supports`/`does_not_support`. Matches
  `TERM_DEFINITIONS["supports 2026-07-28"]` exactly (SDK floor + source
  handler, both already computed by `detect.detect_features`).
- **Live-discover stratum**: a successful `server/discover` response always
  carries `SERVER_DISCOVER` (per `tier3.py`'s own `_observed_features`) →
  `supports`; anything else → `unknown`, **never** `does_not_support`. This
  isn't a simplification — `tier3.py`'s own docstring (requirement 3) says a
  non-answer is indistinguishable from an explicit rejection by design, so a
  probe can prove reachability+support and stop, never prove absence. I
  treated this as a hard constraint on the data, not a gap to paper over: the
  report says so explicitly ("this stratum does not report a
  does-not-support count") rather than inventing a negative signal the probe
  never actually produced.

Fetch failures (`run.fetch_failures`) stay a separate, always-shown top-level
figure — they're already a `CensusRun` column computed independently of any
record's `feature_set_json`, so folding them into the per-revision
`Aggregate.unknown` would double up a number that's already honestly reported
elsewhere under its own label.

Tier-2 `n` (Task 5's correction): shown **per ecosystem** in a table (npm row,
PyPI row, each with its own examined-count/supports/unknown/share), plus one
pooled row underneath. Pooling npm+PyPI *within* the artifact stratum is
legitimate — feature detection isn't ecosystem-relative the way the tier-2
*ranking* metric is (`SELECTION_METHOD` explicitly says PyPI/npm download
counts aren't comparable; whether a package's source implements
`server/discover` is comparable regardless of ecosystem) — but the
per-ecosystem breakdown is always present and unavoidable, so a reader never
sees an unlabelled single tier-2 `n`.

Empty-state: `probe_agg` is `None` when zero live-discover records exist
(this repo's actual current state), and the template renders "Tier 3
remote-stratum sample: not yet run" in both the headline and the detail
section — never a `0 of 0` percentage. Tested by
`test_live_discover_stratum_honest_empty_state`.

`export_raw`'s `salt`: used to compute a **fresh** digest via
`PackageCoords(...).digest(salt)` (falling back to a registry-id-keyed
`blake2b` for coords-less records, mirroring `census/run.py`'s own
`_digest_for`) rather than reusing `CensusRecord.coords_digest`. That DB
column was computed with a per-run salt `run_census` generates and never
persists (a documented `ponytail` gap in Task 6a) — it cannot be reproduced
later, so it isn't a usable basis for the published digest. The caller-
supplied `salt` parameter is the only durable salt that ever exists; I did
not build any generation/storage for it, per the task's explicit scope
limit.

**Design addition beyond the brief, and why**: `export_raw` also writes a
`records.summary.json` sidecar (the same `aggregate()` figures the report
states), and the CSV gained a `stratum` column (`artifact`/`probe`/
`unattempted`) beyond the brief's original single-stratum column list. Both
were necessary to make Step 4's reproducibility claim ("recomputes every
number in the report... prints them beside the published figures with a
pass/fail per line") actually true for two strata rather than hand-waved —
without a stratum discriminator in the CSV, a stranger can't tell an artifact
row from a probe row; without *some* published reference figure, "beside the
published figures" has nothing to compare against. `census_analysis.py`
itself stays stdlib-only with no `agent_perimeter` import, so the check is
two independently-written computations agreeing, not the report trusting its
own aggregation code.

## TDD evidence

RED: `uv run pytest tests/report/test_census_report.py` failed with
`ModuleNotFoundError: No module named 'agent_perimeter.report.census_report'`
before any implementation existed.

GREEN: after implementing `census_report.py` + template, all 13 initial
tests passed; after adding the two extra coverage-closing tests (see below),
19/19 pass. Final full-suite run: `592 passed` (up from 591 pre-task),
`uv run ruff check .` clean, `uv run mypy --strict agent_perimeter` clean
(93 files, including test/factory/analysis files I additionally checked).
`census_report.py` itself: 100% line coverage.

## Files changed

- `agent_perimeter/report/census_report.py` (new)
- `agent_perimeter/report/templates/census.html.j2` (new)
- `analysis/census_analysis.py` (new)
- `docs/census/CHANGELOG.md` (new)
- `tests/report/factories.py` (new)
- `tests/report/test_census_report.py` (new)

Commit: `89b56a5` — "feat: two-stratum census report with defined terms and
raw data export"

## Self-review findings (fixed before commit)

1. **Factory bug**: `census_fixture(names=..., probe_supports=...)` had an
   early `return` inside the `if names is not None` branch that silently
   dropped `probe_supports`/`probe_unknown` records. This meant my raw-export
   stratum-column test wasn't actually exercising a probe row, and
   `_digest_for`'s coords-less fallback branch was uncovered. Fixed the
   factory to only special-case the artifact-record construction, not the
   whole function, then re-verified the fallback branch is now hit.
2. **mypy strict on `census_report.py`'s literal `.__dict__` use** for
   JSON-serializing `Aggregate` — a `slots=True` dataclass has no
   `__dict__`, so this would have raised `AttributeError` at runtime the
   first time `export_raw` ran with a non-empty stratum. Caught before it
   ever shipped (mypy didn't catch this one — a manual re-read did after
   writing the summary-JSON code); replaced with `dataclasses.asdict()` via
   a small `_agg_dict()` helper.
3. **Apostrophe-escaping**: `TERM_DEFINITIONS`'s text contains apostrophes
   (e.g. "package's"). Jinja2's default autoescape converts `'` to `&#39;`,
   which would have broken the brief's exact-substring test
   (`TERM_DEFINITIONS[term] in html`). Fixed by rendering term definitions
   (and `SELECTION_METHOD`) with the `|safe` filter — safe here since both
   are static, project-authored strings, never user input.
4. Added `test_a_record_outside_both_strata_is_skipped_not_miscounted` to
   directly exercise `_classify`'s `None` return path (a tier-1-only /
   never-attempted record must never be counted as `does_not_support`) —
   this closed the last coverage gap in `census_report.py` and pins down a
   design decision that was previously only implicit.

Confirmed via self-review checklist: two strata are never summed anywhere in
the render path (grepped the template and the module for every
`artifact_agg`/`probe_agg` usage — always in separate expressions); the
live-discover empty state is honest and tested; per-ecosystem tier-2 numbers
are shown and tested; all 7 of the brief's original requirements hold; no
salt-persistence machinery was built; `"vulnerable"` is asserted absent
including in the two-stratum template additions specifically.

## Concerns / judgment calls worth flagging

- **`docs/security.md` doesn't exist yet** (that's Task 8). The template
  links to it (`../../security.md`, correct relative path for a report
  published at `docs/census/<date>/`) — a forward reference, not a broken
  build; nothing in this task's test suite checks link resolution.
- **No real census has ever run** in this codebase (Tier 3 isn't wired into
  `run_census`, and Task 4's `SDK_FLOOR` is an unverified placeholder per
  `docs/methodology.md`). `docs/census/CHANGELOG.md` states this plainly
  rather than fabricating a "first publication" entry with invented numbers,
  which the brief's own template literally shows as `<n>`/`<v>`/`<h>`
  placeholders — I read that as an example format to fill in later, not an
  instruction to publish fake statistics now.
- The `records.summary.json` sidecar and the CSV's `stratum` column are my
  own additions beyond the brief's literal column list, justified above.
  Flag for whoever reviews the whole branch: if a different reproducibility
  mechanism is preferred (e.g., embedding expected figures directly in
  `census_analysis.py` per dated report instead of a sidecar file), this is
  the place to reconcile it.
