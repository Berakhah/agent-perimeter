# Task 16 report — Accessibility, keyboard and print verification

## What was implemented

1. **RED harness** — `web/tests/a11y.spec.ts` and `web/tests/print.spec.ts`, verbatim from the
   brief (a11y across all 6 screens; print.spec.ts's 3 report tests plus the Step 5 census test).
2. **`pretest` fixture rendering** (ruling 1) — `analysis/render_web_fixtures.py`, a direct call to
   `report/html.py::render_report` and `report/census_report.py::render_census` using
   `tests/report/factories.py`/`test_html.py`'s existing sample data. `web/package.json`'s
   `pretest` script runs it; `web/tests/global-setup.ts` calls `npm run pretest` from Playwright's
   `globalSetup` hook, because npm's `pretest` lifecycle only fires ahead of `npm test`, never
   ahead of `npx playwright test` — which is exactly how this project's CI and every local
   invocation runs the suite. Without `global-setup.ts` the brief's own given CI YAML would never
   render the fixtures at all.
3. **Template testids** (rulings 2–3) — `report.html.j2` (`methodology-footer`, `severity-badge`,
   `finding-row`) and `census.html.j2` (`population-size`, `tier2-n`, `unknown-count`,
   `fetch-failures`, `term-definitions`).
4. **Print CSS** (ruling 4) — `report.css` gained `break-inside: avoid` for `[data-testid="finding-row"]`.
5. **`web/playwright.config.ts`** — `webServer` converted to a 2-entry array; Task 10's dev-server
   entry preserved byte-for-byte, new entry serves `tests/fixtures/` on port 4173 via `serve` (new
   MIT dev dependency).
6. **`web/app/print.css`** — dedicated print stylesheet for the 5 Next.js screens (screen 6 has its
   own, verified separately).
7. **CI** — new `web:` job in `.github/workflows/ci.yml`, per the brief, plus `astral-sh/setup-uv@v3`
   + `uv sync --all-groups` (not in the brief's sketch, but required — the `pretest` step shells
   out to `uv run python`).
8. **Real screen/component fixes** — see enumerated list below.

## TDD evidence

**RED** (before any GREEN fix, first real run against the newly-created spec files + rendered
fixtures):

```
npx playwright test tests/a11y.spec.ts --reporter=list
```
9 failures on first full run (after ruling-driven template/testid fixes were already in place, so
these are the genuine screen-level gaps, not setup errors):
- `scan setup has no serious or critical axe violations` — color-contrast, `.bok-lock-reason`
- `findings has no serious or critical axe violations` — color-contrast
- `drift has no serious or critical axe violations` — color-contrast, `.bok-diff-word-added`
- `live scan is fully operable from the keyboard` / `has a visible focus ring`
- `drift is fully operable from the keyboard` / `has a visible focus ring`
- `report has a visible focus ring`
- `report is usable at 375px`

(An axe violation with a JSON diff, a `reachable.size` assertion, and a `scrollWidth`
assertion — none of these were setup/harness failures; every one traces to real markup/CSS.)

**GREEN**:

```
npx playwright test tests/a11y.spec.ts tests/print.spec.ts --reporter=list
28 passed (23.7s)

npx playwright test --reporter=list      # full suite, all 6 tasks' specs together
62 passed (~20-58s across 6 separate runs)
```

Full suite (`npx playwright test`, all spec files) run **6 times** across this session: 5 clean
62/62, 1 run had a single flaky failure in `graph.spec.ts`'s pre-existing (Task 14) "the graph is
fully navigable from the keyboard" test — reproduced-in-isolation as passing, and confirmed clean
on 3 subsequent full-suite runs. Traced to test-harness timing under 11-worker parallel load, not
a logic regression: my only change to `ProvenanceRail` (making `inert` declarative) makes the
open-transition *more* synchronous, not less, and this same test's flakiness during its own Task 14
implementation is independently documented in this project's own ledger (`progress.md`,
"Accessibility fix regressed keyboard navigation test for ProvenanceRail", same day, before this
task started). Not treated as a Task 16 regression; flagged here for visibility.

Python side: `uv run pytest -q` — 618 passed, 93.87% coverage. `uv run mypy --strict agent_perimeter`
— clean. `uv run ruff check agent_perimeter analysis` — clean. `npx tsc --noEmit` / `npm run lint`
— clean, 0 warnings. `npm run build` — production build succeeds.

## Every real accessibility/print/responsive issue found and fixed

1. **`report.html.j2`'s embedded stylesheet was being HTML-escaped.** `<style>{{ css }}</style>`
   (no `|safe`) turned every `"` into `&#34;` inside a `<style>` block — invalid inside raw-text
   elements, corrupting `font-family: "IBM Plex Mono", ...` and the print `content: attr(...) " ";`
   glyph-spacing rule. `census.html.j2` already had this fixed (visible in the project's own commit
   history); `report.html.j2` never got the same fix. **Fixed**: added `|safe`.
2. **Color contrast (axe `color-contrast`, serious) on 4 design tokens.** `--severity-medium`
   (3.1:1), `--severity-high` (4.06:1, latent — not hit by the current fixtures but reachable by
   any HIGH-severity finding badge), `--provenance-verified` (3.9:1), `--provenance-unverified`
   (3.8:1) all measured below WCAG 2 AA's 4.5:1 floor against `--paper` when used as text color
   (`.bok-lock-reason`, `.bok-diff-word-added`, severity badges, provenance labels). Measured with
   a canvas-pixel-sampling script against the real `oklch()` → sRGB conversion Chromium performs
   (not hand-computed) to pick replacement values. **Fixed**: darkened lightness only (same
   hue/chroma family) — new contrasts 5.7–8.9:1. This token ramp is explicitly called out in its
   own comment as "not the final `bok-ui` token sheet," unlike the pinned paper/ink/accent values.
3. **Capability-graph focus rings removed, not replaced.** `.bok-graph-node-tool:focus-visible`
   and `.bok-graph-edge:focus-visible` both set `outline: none` and relied only on an SVG `stroke`
   change — invisible to the RED test's `getComputedStyle(...).outlineStyle !== "none"` check (and
   a real WCAG 2.4.7 gap for anyone who can't perceive the stroke change). **Fixed**: restored a
   real `outline: 2px solid var(--accent)` on both, kept the stroke change as a secondary cue.
4. **`ProvenanceRail`'s `inert` had a real timing gap.** `railRef.current.inert = !open` was only
   ever set imperatively inside a `useEffect`, so from first paint/hydration until that effect
   committed, the DOM had `aria-hidden="true"` on the closed rail *without* `inert` — exactly the
   "aria-hidden container with a focusable descendant" shape axe-core's `aria-hidden-focus` rule
   (serious) flags, caught on the capability-graph screen. **Fixed**: `inert={!open}` as a
   declarative JSX prop (React 19 reflects `inert` natively), so it's correct from the very first
   render — no effect, no window.
5. **`FindingsTable` (7 fixed-160px columns) overflows any viewport under ~1120px.**
   `.bok-table-scroll` only had `overflow-y: auto`. **Fixed**: added `overflow-x: auto`.
6. **Capability graph's accessible-alternative table had no scroll wrapper**, and its `rationale`
   column's free text pushed it wider than 375px. **Fixed**: wrapped it in a scrollable container
   (`.bok-graph-table-scroll { overflow-x: auto }`), gave the table a `min-width` so it scrolls
   rather than compresses illegibly.
7. **Live-scan check rows overflow 375px with a long check id.** `.bok-check-row` is a flex row
   with `justify-content: space-between`; a flex child's default `min-width: auto` refuses to
   shrink below its content's intrinsic width, and a dotted identifier like
   `revision.header_annotation_unreachable` has no natural break point. **Fixed**: `flex-wrap:
   wrap` on the row, `min-width: 0` + `overflow-wrap: anywhere` on the id span.
8. **Live-scan and drift screens had no focusable content at all** at the instant the RED
   keyboard/focus-ring tests run (a single, immediate `Tab` press right after `goto`, no wait).
   Both screens are legitimately non-interactive at that moment by design (drift: static
   diff/timeline content; live-scan: nothing has streamed in yet). **Fixed** with real, useful,
   non-invented navigation rather than fabricated chrome: live-scan gained an always-present "View
   findings for this scan" link (`/scans/{id}/findings`); drift's `RunTimeline` gained an optional
   `href` and each scan-history entry now links to `/scans/{id}`.
9. **Findings screen flashed an unfocusable `Skeleton` before real content**, even in fixture mode
   where the data is a synchronous lookup. The `useEffect`-deferred fixture load left a real
   pre-hydration/pre-effect window with zero focusable elements, which the RED test's immediate,
   no-wait single `Tab` press could land in. **Fixed**: refactored to compute fixture data
   synchronously in the render body — the exact fix `graph/page.tsx` (Task 14) already documents
   and applies for the identical reason; only the real (non-fixture) fetch path still uses an
   effect.
10. **`report.html.j2` had zero focusable elements**, so the RED "visible focus ring" test had
    nothing to land on, and the report overflowed at 375px (a 5-column table with unbroken `<code>`
    content, no responsive handling). **Fixed**: linked each finding's CWE to its MITRE definition
    page (`https://cwe.mitre.org/data/definitions/{n}.html`) — real, useful content, not
    decoration, and it activates `report.css`'s previously-dormant `a::after` print rule for the
    first time. Added a narrow-viewport rule (`@media (max-width: 480px) { table { display: block;
    overflow-x: auto; } }`) so a wide table scrolls in its own box.

Ruling 2's own two `toBeHidden()` tests (nav, export button) pass correctly on absence, as
predicted — no chrome was invented to make them "really" test something.

## Files changed

- `agent_perimeter/report/templates/report.html.j2`, `census.html.j2`, `report.css`
- `analysis/render_web_fixtures.py` (new)
- `web/playwright.config.ts`, `web/package.json`, `web/package-lock.json`, `web/.gitignore`
- `web/tests/a11y.spec.ts`, `print.spec.ts`, `global-setup.ts` (new)
- `web/app/print.css` (new), `web/app/layout.tsx`
- `web/app/globals.css`
- `web/app/components/CapabilityGraph.tsx`
- `web/app/scans/[id]/page.tsx`, `scans/[id]/drift/page.tsx`, `scans/[id]/findings/page.tsx`
- `web/src/lib/_bok-ui.tsx`
- `.github/workflows/ci.yml`
- `docs/evidence/print-report.png`, `print-census.png` (new)

## Self-review findings

- Verified every new/changed `data-testid` is unique in its template (no strict-mode Playwright
  collisions) — `population-size`, `tier2-n`, `unknown-count`, `fetch-failures` each appear exactly
  once in `census.html.j2` (`tier2-n`/`unknown-count` both had a second, un-tagged occurrence
  elsewhere in the template — left untagged deliberately).
- Confirmed the two testid insertions that touch existing rendered text (`fetch-failures`,
  `unknown-count`) don't break `tests/report/test_census_report.py`'s substring assertions
  (`"Fetch failures: 0"`, `"12 unknown"`) — both initially did break this exact way on first
  attempt (testid placed as an inline `<span>` around just the number, splitting the substring
  across a tag boundary); fixed by moving the testid to the wrapping block element instead. All 45
  `tests/report/` tests pass.
- Re-ran the full 62-test Playwright suite 6 times total across the session (not just twice) given
  the shared-file blast radius (`_bok-ui.tsx`, `globals.css`, `playwright.config.ts` all touch
  every prior task's specs) — 5/6 clean, 1 pre-existing flaky test (see TDD evidence above), zero
  regressions in any of Tasks 10–15's own spec files.
- `npm audit`: 2 pre-existing vulnerabilities (postcss, via Next's own transitive dependency) —
  unrelated to this task, would require an unvetted Next major bump to fix (out of scope, Next 15
  is deliberately pinned per Task 10's own ruling).
- New dev dependency `serve@14.2.6` (MIT) resolved cleanly; flagged here for Task 17's stated
  licence-audit step, same convention as `@axe-core/playwright` (MPL-2.0) and `hypothesis`
  (MPL-2.0) before it.

## Issues / concerns

- **Pre-existing, out-of-scope formatting drift**: `uv run ruff format --check .` fails on 9 files
  I did not touch (`census/artifacts.py`, `census/sample.py`, `analysis/census_analysis.py`, 5 test
  files, `tests/report/factories.py`) — confirmed via `git status` that none of these are modified
  by this session. This predates Task 16 and isn't something this task's scope covers; flagging so
  it isn't mistaken for something this diff introduced. The existing `test:` CI job's `uv run ruff
  format --check .` step would already be failing on `main` for this reason, independent of
  anything in this branch.
- **Dark mode**: the 4 darkened severity/provenance tokens (fix #2 above) are defined once in
  `:root` with no dark-mode-specific override, same as before my change — darkening them for
  light-mode contrast makes their (already-untuned) dark-mode contrast worse in the same direction,
  not better. Not exercised by any test (Playwright's default color scheme is light, and nothing in
  this app ever sets `data-theme="dark"`), so not caught by this task's gate — but flagged
  explicitly as a known gap for whoever eventually builds out real dark-mode QA, rather than
  silently left for a future session to rediscover.
- The one flaky pre-existing test (`graph.spec.ts`, described above) is not fully explained beyond
  "timing under parallel load" — genuinely reproduced as passing in isolation and on 3 subsequent
  full runs, and its flakiness during its own original implementation is independently documented
  in this project's ledger, so judged pre-existing rather than a Task 16 regression, but noted
  rather than asserted with full certainty.
