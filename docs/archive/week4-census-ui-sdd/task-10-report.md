# Task 10 report: Web scaffold, tokens and the `bok-ui` contract

## What I implemented

Scaffolded `web/` from scratch (it did not exist before this task):

1. **Next.js 15 app** via `npx create-next-app@15 . --typescript --tailwind --app --eslint --no-src-dir --use-npm` (per pre-flight ruling 1; resolved to 15.5.25). Used `CI=true ... --no-turbopack` to make the scaffold non-interactive (the plain command hangs on a Turbopack prompt with no TTY attached — see "Deviations" below).
2. **`tsconfig.json`**: added `"noUncheckedIndexedAccess": true` (`"strict": true` was already the create-next-app default).
3. **Self-hosted fonts** (per pre-flight ruling 2): installed `geist`, `@fontsource/newsreader`, `@fontsource/ibm-plex-mono` as one-time file sources, copied a minimal weight set into `web/src/fonts/`:
   - `newsreader/` — 400 normal, 400 italic, 600, 700 (display/report headings)
   - `geist-sans/Geist-Variable.woff2` — one variable-font file covers the full weight range (UI)
   - `ibm-plex-mono/` — 400, 600 (data/code, tabular numerals)
   Loaded via `next/font/local` in `web/app/layout.tsx`. Uninstalled the three source packages afterward (`npm uninstall geist @fontsource/newsreader @fontsource/ibm-plex-mono`) — the `.woff2` files are copied out, the packages are not a runtime need. Confirmed all three are OFL-licensed (`node_modules/.../LICENSE*` inspected before uninstall).
4. **`web/app/globals.css`**: the OKLCH token ramp — `paper`/`ink`/`accent` at 00 §5.2's exact values, a derived 12-step warm-graphite neutral ramp, severity scale (critical/high/medium/low/info) and provenance-state scale (verified/modelled/unverified), all wired through Tailwind v4's `@theme inline`. Dark-mode tokens under both `prefers-color-scheme` and `[data-theme="dark"]`. Three density modes (`comfortable`/`compact`/`dense`) as CSS custom properties, defaulting to `compact` via `<html data-density="compact">` in `layout.tsx`. `.bok-numeric { font-variant-numeric: tabular-nums }` plus every `bok-*` component class the stand-ins reference. `prefers-reduced-motion` kill-switch and a `.bok-no-print` print rule.
5. **`web/src/lib/_bok-ui.tsx`**: real, minimal implementations of all 12 components from 00 §5.4 — `Claim`, `ProvenanceRail`, `SeverityBadge`, `FindingsTable`, `EvidencePane`, `ConfidenceMeter`, `QuotaStrip`, `RunTimeline`, `DiffView`, `EmptyState`, `ErrorState`, `Skeleton` — documented at the top of the file as a stand-in with the same swap path as `agent_perimeter/_contracts.py` (delete the file, import from `@backoffice-kit/bok-ui` once it ships). Key behaviours:
   - `Claim` takes `derivation: "schema"|"description"|"probe"|"artifact"`, each rendered with a distinct glyph (`▣`/`✎`/`◎`/`▤`) + accessible label, dotted-underline styling per 00 §5.3, and `onActivate` (click, Enter/Space, or Cmd/Ctrl+.) to open a rail.
   - `ProvenanceRail` renders a 380px right-hand panel, the chain top-to-bottom (value, method+derivation glyph, source link/file:line, confidence with calibration state, timestamp, caveat), 180ms slide transition with a 30ms per-item stagger, all disabled under `prefers-reduced-motion` (global CSS rule, not per-component logic).
   - `SeverityBadge` renders a 4-block fill glyph (`▰▰▰▰` down to `▱▱▱▱`) plus the text label — never colour alone; `data-glyph` + non-empty text on every badge.
   - `FindingsTable` — column-resizable (drag handles on `<th>`), keyboard-navigable (roving tabindex, arrow keys), CSV/JSON export. The provenance column is glyph+label (requirement 2) and CSV export includes it explicitly (`toCsv()` always writes the derivation label column). Row virtualisation is **deliberately deferred** — `ponytail:` comment naming the ceiling (fine for small fixture/demo row counts; swap in `@tanstack/react-virtual` if a real scan's row count matters).
   - `ConfidenceMeter` defaults `calibrated` to `false` — uncalibrated is the state you get without passing anything, greyed via `.bok-confidence-uncalibrated`, calibration is what must be supplied (00 §B10 / the brief's requirement 3).
   - `EvidencePane`, `QuotaStrip`, `RunTimeline`, `DiffView`, `EmptyState`, `ErrorState`, `Skeleton` — real, minimal implementations; `DiffView`'s line-set diff and the lack of table virtualisation are the two `ponytail:`-flagged simplifications in the file.
6. **`web/src/lib/api.ts`**: thin typed client for the Task 9 API — `createScan`, `getScan`, `getFindings`, `getGraph`, `getSarifReport`, `getCensusRun`, `subscribeToScanEvents` (SSE via `EventSource`). Types read directly from `agent_perimeter/api/{scans,census,schemas}.py` and `checks/registry.py::SkipReason`, not the plan's sketch. `findings`/`graph` stay `unknown[]` per the ruling — Task 11+'s job to narrow.
7. **`web/app/findings/page.tsx`**: a fixture-only route (`?fixture=mixed` → 5 rows spanning all 5 severities and all 4 derivations) that exercises `FindingsTable` end to end. Not in the brief's "Files" list verbatim, but required for `tests/tokens.spec.ts` to exercise anything real — without it `page.goto("/findings?fixture=mixed")` 404s and the severity-badge test would pass vacuously (empty row list). Documented in the file as what Task 11 replaces with the real API-wired screen.
8. **`web/playwright.config.ts`**: not in the brief's Files list either, but nothing else in the plan owns it and `npx playwright test` needs one — `webServer` running `next dev` on port 3100, chromium project.
9. **`web/next.config.ts`**: added `allowedDevOrigins: ["127.0.0.1", "localhost"]` to silence a Next 15 dev-only cross-origin warning that otherwise polluted test output (Playwright's webServer talks to the dev server via `127.0.0.1`).
10. Replaced the create-next-app boilerplate `app/page.tsx` (Next.js/Vercel marketing links, unused `Image` imports) with a two-line placeholder; deleted the now-unreferenced default SVGs under `public/`.

## What I tested

- `npx tsc --noEmit` — clean, no errors (including after adding `noUncheckedIndexedAccess`, which required a small refactor in `FindingsTable`'s ref-callback code — see below).
- `npm run lint` (`eslint`, flat config, `next/core-web-vitals` + `next/typescript`) — clean, no warnings.
- `npx playwright test tests/tokens.spec.ts` — 3/3 passing, pristine output (no warnings after the `allowedDevOrigins` fix).
- `npm run build` (`next build`) — compiles and prerenders cleanly (not in the brief's verify list, ran it anyway since this is a scaffold everything else builds on): `/` static, `/findings` dynamic (reads `searchParams`), 103 kB shared JS.

### TDD evidence

**RED** — `npx playwright test tests/tokens.spec.ts`, run after the scaffold/fonts/tokens-CSS-baseline existed but before `_bok-ui.tsx`, `api.ts`, or `app/findings/page.tsx`:

```
Running 3 tests using 3 workers
  ok 3 [chromium] › tests\tokens.spec.ts:20:5 › no external host is contacted (1.7s)
  ok 1 [chromium] › tests\tokens.spec.ts:3:5 › severity is never encoded in colour alone (1.7s)
  x  2 [chromium] › tests\tokens.spec.ts:14:5 › numbers are tabular (6.7s)

  1) [chromium] › tests\tokens.spec.ts:14:5 › numbers are tabular ────
    Error: expect(locator).toHaveCSS(expected) failed
    Locator: getByTestId('numeric-cell').first()
    Expected pattern: /tabular-nums/
    Timeout: 5000ms
    Error: element(s) not found
  1 failed, 2 passed (45.5s)
```

Expected failure: `/findings` didn't exist yet, so `getByTestId("numeric-cell")` never appears and the assertion times out. Worth noting honestly: tests 1 and 3 passed *vacuously* at this point — test 1's `for (const row of await page.getByRole("row").all())` iterates zero times against a 404 page (the loop body never runs, so nothing is asserted), and test 3 was already satisfied because the font/CDN work in `layout.tsx` was already correct. Only test 2 gives real RED signal here; after implementation, test 1 is verified to genuinely exercise 5 real rows (see GREEN below), not just pass by absence.

**GREEN** — same command, after `_bok-ui.tsx`, `api.ts`, `app/findings/page.tsx`, and the full token/component CSS existed:

```
Running 3 tests using 3 workers
  ok 2 [chromium] › tests\tokens.spec.ts:20:5 › no external host is contacted (2.9s)
  ok 3 [chromium] › tests\tokens.spec.ts:14:5 › numbers are tabular (3.0s)
  ok 1 [chromium] › tests\tokens.spec.ts:3:5 › severity is never encoded in colour alone (3.1s)
  3 passed (11.0s)
```

Re-ran once more after removing the one-time font-source npm packages and once more after the final SVG cleanup — still 3/3, pristine, no change in behaviour (confirms the copied `.woff2` files are genuinely self-contained, not still reaching into `node_modules`).

## Files changed

All new (`web/` did not exist before this task):

- `web/package.json`, `web/package-lock.json`, `web/tsconfig.json`, `web/next.config.ts`, `web/eslint.config.mjs`, `web/postcss.config.mjs`, `web/.gitignore`, `web/README.md` (create-next-app default, untouched)
- `web/app/layout.tsx`, `web/app/globals.css`, `web/app/page.tsx`, `web/app/favicon.ico`
- `web/app/findings/page.tsx` (fixture route, not in brief's Files list — see note above)
- `web/src/lib/_bok-ui.tsx`, `web/src/lib/api.ts`
- `web/src/fonts/{newsreader,geist-sans,ibm-plex-mono}/*.woff2` (7 files)
- `web/tests/tokens.spec.ts` (verbatim from the brief)
- `web/playwright.config.ts` (infra, not in brief's Files list — see note above)

## Self-review findings

- **`noUncheckedIndexedAccess` surfaced a real gap in `FindingsTable`**: the original ref-callback code (`cellRefs.current[rowIndex][col] = el`) relied on a `??=` assignment happening on a *different* line than the read, which `tsc` correctly flagged as possibly-undefined. Fixed with a `setCellRef(row, col)` factory that does the `??=` and the write together, so the array is provably defined at the write site. Not a cosmetic type-check dodge — this was an actual latent bug (a row array could have been read before being initialized in some render orderings).
- **api.ts's SSE terminal-frame shape diverges from the pre-flight ruling's literal wording.** The ruling states the terminal frame is the same shape "plus `skipped`"; reading `agent_perimeter/api/events.py::EventLog.finish` directly shows the terminal frame is a *distinct* shape — `{terminal: true, completed, total, skipped: [...]}` — that never carries `check_id`/`status`/`elapsed_ms`/`phase` at all. I modeled `ScanEvent` as a discriminated union (`ScanCheckEvent | ScanTerminalEvent`) with an `isTerminalEvent()` type guard, matching the real code rather than the ruling's simplified prose. This is exactly the kind of drift ruling 3 says to avoid ("saves Task 11 from discovering drift") — flagging it explicitly since it's a correction to dispatch text, not an error in it that needed fixing.
- **`FindingsTable`'s provenance column reuses the `Derivation` vocabulary** (schema/description/probe/artifact) rather than inventing a second `verified/modelled/unverified` axis for that column. 00 §5.2 defines both scales but doesn't say which one the *table's* provenance column shows. I used derivation there (it's what's actually available per-row from a `Finding`'s `Claim`) and reserved the verified/modelled/unverified scale for `ProvenanceRail`'s per-chain-entry state tag (inferred from `method`, overridable). Both scales are real, defined, and consumed by a real component — just not by the same component. Worth `backoffice-kit` confirming this mapping when the real package is designed.
- **Severity and provenance-state OKLCH values beyond `paper`/`ink`/`accent` are my own derivation**, not values 00 §5.2 specifies (it only pins those three). Picked to stay in the same warm-graphite/print-safe family; not the final token sheet. Same caveat class as `_contracts.py`'s existing placeholder confidence values — flagged in the file's own doc comment, should go to the `backoffice-kit` session alongside the three explicit requirements the brief already calls out.
- Two `ponytail:`-flagged deliberate scope cuts inside `_bok-ui.tsx`: `FindingsTable` has no row virtualisation (fine at fixture/demo scale; upgrade path named inline), and `DiffView` does a naive line-set diff rather than a real LCS/Myers alignment (upgrade path named inline).
- `npm audit` reports 2 vulnerabilities (1 moderate, 1 high) inherited from create-next-app's default toolchain dependency tree (not from anything I added — the font-source packages were fully removed). Could not get further detail: `npm audit`/`npm audit --json` hung against the registry in this sandbox (network-restricted) rather than returning promptly; not investigated further. Flag for whoever runs the final whole-branch dependency/licence audit (Task 17's stated job).

## Deviations from the brief worth flagging explicitly

1. **Scaffold command needed `CI=true` and `--no-turbopack`**, not just the brief's plain `npx create-next-app@15 . --typescript --tailwind --app --eslint --no-src-dir --use-npm`. Recent `create-next-app` versions prompt interactively for Turbopack; with no TTY attached that prompt hangs forever rather than failing loudly. `CI=true` plus explicit `--no-turbopack` makes the scaffold deterministic and non-interactive. Everything else in the brief's Step 1 command ran as written.
2. **`web/app/findings/page.tsx` and `web/playwright.config.ts`** are not in the brief's "Files:" list but are load-bearing for the "Test:" line to mean anything (a Playwright test needs a server config to run against, and `page.goto("/findings?fixture=mixed")` needs a page to exist or the severity-badge test passes vacuously). Both are documented as scaffold-only / fixture-only, explicitly deferring the real implementation to Task 11.

## Concerns

None blocking. The two `bok-ui`-requirements-worth-flagging items above (severity/provenance-state token values being my own placeholders; the derivation-vs-provenance-state column mapping choice) should reach whoever builds the real `backoffice-kit` package, same as the three requirements the task-10 brief already names.

---

## Fix report — review round 1 (4 Important findings)

All four fixed. Commands and output below; details per finding follow.

### Commands run after fixing

```
npx tsc --noEmit
```
Output: clean, no errors.

```
npm run lint
```
Output:
```
> web@0.1.0 lint
> eslint
```
Clean, no warnings.

```
npx playwright test
```
Output:
```
Running 4 tests using 4 workers
  ok 3 [chromium] › tests\tokens.spec.ts:20:5 › no external host is contacted (1.8s)
  ok 2 [chromium] › tests\tokens.spec.ts:3:5 › severity is never encoded in colour alone (1.9s)
  ok 4 [chromium] › tests\tokens.spec.ts:14:5 › numbers are tabular (1.8s)
  ok 1 [chromium] › tests\provenance-rail.spec.ts:7:5 › a closed provenance rail has no reachable descendants, and focus moves correctly (2.0s)
  4 passed (7.6s)
```
4/4 passing, pristine output.

```
npm run build
```
Output: compiles cleanly, `/findings` now 10.4 kB (up from 1.85 kB — the new `ProvenanceDemo` client island + `@tanstack/react-virtual`), `/` unaffected, no warnings.

### Finding 1 — `FindingsTable`'s `density` prop was dead code

Fixed via option (a): added the missing CSS. `web/app/globals.css` now has `.bok-table-wrap.bok-density-{comfortable,compact,dense}` rules that set the same `--density-cell-y`/`--density-cell-x`/`--density-gap` custom properties the global `html[data-density="..."]` rule sets, but scoped to the table wrapper. CSS custom properties inherit down the actual DOM tree (not by selector specificity across elements), so the wrapper's own value — being the nearer ancestor — now correctly overrides the page-level one for just that table. Passing `density="dense"` to one `FindingsTable` now changes only that table's row height/padding, independent of the page's `data-density` attribute.

### Finding 2 — `Derivation` type was missing `"name"`

Added `"name"` as a 5th member of `web/src/lib/_bok-ui.tsx`'s `Derivation` type, matching `agent_perimeter/_contracts.py::Derivation` exactly (SCHEMA/NAME/DESCRIPTION/PROBE/ARTIFACT). Added a `DERIVATION_META.name` entry (glyph `#`, label "Name") so `Claim`, `FindingsTable`'s provenance column, and `ProvenanceRail`'s per-entry derivation tag all render it correctly instead of hitting `undefined` on a live `Finding` whose claim derivation is `"name"`. Updated the doc comments citing `_contracts.py` to say "all 5 members" instead of listing 4.

### Finding 3 — `ProvenanceRail` trapped focusable elements behind `aria-hidden` when closed

Added a `railRef` on the `<aside>` and an effect that sets the real DOM `inert` property (`railRef.current.inert = !open`) — not a CSS-only visual hide, an actual browser-level removal of focusability and click-handling for the whole subtree, which is what makes `aria-hidden={!open}` true rather than a lie axe-core would flag (an aria-hidden container with a focusable descendant). Added focus management: opening the rail captures `document.activeElement` as the trigger and moves focus to a new `closeButtonRef`-tracked close button; closing it returns focus to the captured trigger.

**Verified the fix is load-bearing, not decorative**: temporarily commented out the `inert` assignment, re-ran the new test, watched it fail exactly as expected (`toHaveJSProperty("inert", true)` — received `false`), then restored the fix and confirmed it passes again. Transcript:

```
Error: expect(locator).toHaveJSProperty(expected) failed
Locator:  getByTestId('provenance-rail')
Expected: true
Received: false
```

**New covering test**: `web/tests/provenance-rail.spec.ts`. Exercises the fixture `/findings` page's new `ProvenanceDemo` section (a `Claim` wrapping a confidence value, wired to open a `ProvenanceRail` with one demo chain entry — added specifically so this fix has a real page to test against, matching the existing `?fixture=` pattern). Asserts: closed rail is `inert`; clicking the `Claim` opens it (`inert` false, close button focused); `Escape` closes it (`inert` true again, focus back on the `Claim`).

### Finding 4 — `FindingsTable` shipped without virtualisation

Installed `@tanstack/react-virtual` (MIT-licensed, confirmed via `node_modules/@tanstack/{react-virtual,virtual-core}/package.json` before adding — compliant with CLAUDE.md's Apache/MIT/BSD-only dependency policy), then uninstalled the three font-source packages did not touch it (separate `npm i`/`npm uninstall` pass, done earlier).

Implementation: `FindingsTable` now wraps the `<table>` in a `.bok-table-scroll` div (`overflow-y: auto`, `max-height` = 12 rows at the current density's fixed row height) and drives `tbody` rendering through `useVirtualizer`. Uses the standard "windowed native table" pattern — real `<tr>` elements only for the currently-visible range (`overscan: 8`), with a padding-top and padding-bottom spacer `<tr>` (a single cell, `colSpan` across all columns, `aria-hidden="true"`) standing in for the off-screen rows' total height — rather than absolutely-positioned rows, which would break native table layout semantics. Row height is a fixed per-density constant (`ROW_HEIGHT_BY_DENSITY`), not `measureElement`-based dynamic sizing: every cell in this stand-in's rows is single-line, so the constant is exact, not approximate — a `ponytail:` comment names dynamic sizing as the upgrade path if a column ever wraps.

Column-resize, keyboard-nav, and CSV/JSON export are all unchanged in behavior — verified by the fact that `tests/tokens.spec.ts`'s existing 3 tests (which exercise severity glyphs and numeric-cell tabular-nums across all 5 fixture rows) still pass unmodified after this change, meaning every row is still correctly reachable and rendered at the small fixture scale.

**Known, disclosed limitation** (not fixed this round, matches the reviewer's "don't over-build" allowance): keyboard arrow-navigation only focuses currently-*mounted* rows — a row scrolled out of the virtualizer's window has no ref to focus yet. Harmless at fixture/demo scale (the whole 5-row table fits inside the scroll container without scrolling, so nothing is ever actually virtualized out in this task's own usage), flagged inline with a `ponytail:` comment naming `rowVirtualizer.scrollToIndex()` as the upgrade path if real scan-sized tables make this a live user complaint.

### Files changed (this round)

- `web/src/lib/_bok-ui.tsx` — all 4 fixes
- `web/app/globals.css` — Finding 1's density CSS, `.bok-table-scroll`/sticky-header CSS for Finding 4
- `web/app/findings/page.tsx` — renders the new `ProvenanceDemo` section
- `web/app/findings/ProvenanceDemo.tsx` — new, fixture-only `Claim`/`ProvenanceRail` wiring for Finding 3's test
- `web/tests/provenance-rail.spec.ts` — new, covers Finding 3
- `web/package.json` / `web/package-lock.json` — added `@tanstack/react-virtual` (MIT)

### Self-review of this round

- Re-confirmed no regressions: full `npx playwright test` run (4/4) covers both the pre-existing token behaviour and the new rail test in one pass.
- Did not touch the three items the reviewer explicitly marked out of scope for this round (static roving-tabindex reset, no keyboard equivalent for the resize handle, licence audit, `revokeObjectURL` ordering).
- `next build` re-run to confirm the new dependency and client component don't break production bundling — clean, `/findings`'s bundle grew as expected (virtualizer + rail demo code), `/` untouched.
