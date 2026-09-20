# Agent Perimeter — Data-Dense Ops Console (Serif Accent)

**Date:** 20 September 2026
**Status:** brainstormed, plan pending execution
**Scope:** typography scale, elevation/surface tokens, and three new
decorative data-visualization components in the five Next.js screens under
`web/app/**` and the shared component library (`web/src/lib/_bok-ui.tsx` and
a new `web/src/lib/_bok-viz.tsx`). Does **not** touch the Python-rendered
static `report.html`/`census.html` artifacts
(`agent_perimeter/report/templates/*.j2`) — a separate subsystem requiring
its own plan (see §7).
**Consumes unchanged:** `--paper`/`--ink`/`--accent` (pinned, 00 §5.2), the
severity/provenance color ramps, radius tokens, and the three typefaces
already loaded in `web/app/layout.tsx` (Newsreader, Geist Sans, IBM Plex
Mono).

---

## 1. Why

Manual UI testing after the 2026-09-17 motion/spacing redesign (task
S270/S272 in project memory) surfaced "boring UI" feedback: the dense
ops-console layout reads as one flat visual register — one typeface doing
every job, one background lightness for page and panel alike, and no
at-a-glance summary of scan results anywhere except the raw table. Three
design directions were mocked in a visual-companion browser session; **Data-
Dense Ops Console** was selected, and within it, **Serif Accent** heading
treatment (Newsreader for titles/section heads, IBM Plex Mono for data, Geist
Sans for body) over a single heavy-sans voice — chosen for the added
type-voice contrast between narrative headings and tabular data, which a
security posture tool's dense screens benefit from.

## 2. Decisions taken (brainstorming, 20 Sep 2026)

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | Heading typeface | **Newsreader (serif)** for `h1`/`h2`/section/panel headings — two distinct voices (serif headings, mono data) instead of one heavy-sans voice throughout. | Heavy Sans: bold, tight-tracking Geist for all titles — a single console-native voice. Rejected by direct user pick ("B — Serif Accent"). |
| D2 | Type scale | New `--text-xs` (11px) → `--text-3xl` (28px) scale in `:root`, applied to headings and the new viz components' numbers. Existing hardcoded `em`/`rem` sizes elsewhere in `globals.css` are left as-is — this pass targets headings and new components only, not a full typography audit. | Rewriting every existing font-size declaration onto the new scale — out of scope, unrelated regression risk. |
| D3 | Elevation model | Three background-lightness steps (`--surface-0/1/2`) plus a 1px hairline border and a 1px inset top highlight on panels — no drop shadows (read poorly on the near-black dark theme). | Box-shadow-based elevation — rejected for the dark-theme rendering reason above. |
| D4 | Severity encoding | Add a low-opacity tinted chip background behind the existing bar-glyph+label `SeverityBadge`, derived from the existing `--severity-*` tokens at low alpha via `color-mix`. Glyph + label remain the actual encoding; color is additive only. | Making the chip background the primary severity signal — would violate 00 §5.2's "never colour-alone" rule. |
| D5 | New viz components | Three dependency-free (hand-rolled SVG/CSS) components: `StatTileGrid`, `Sparkline`, `SeverityDistributionBar`. All decorative summaries of data already rendered accessibly elsewhere (`aria-hidden="true"` + adjacent accessible text), matching the existing `SeverityBadge` glyph pattern. | A charting library (Recharts, visx, etc.) — would add a dependency and bundle-size cost the way `motion` already did (task 7 memory: "Bundle-Size Budget Exceeded by All Routes"); also risks an AGPL/incompatible license (CLAUDE.md dependency floor). |
| D6 | `Sparkline` empty state | Render nothing (not a flat placeholder line) when fewer than 2 data points exist. | A synthetic flat-line placeholder — would be fabricated data, which CLAUDE.md's copy rules and the existing drift-screen "single scan" honest-empty-state test both forbid. |

## 3. Typography system

| Voice | Font | Used for |
|---|---|---|
| Display | Newsreader (`--font-newsreader`, already loaded) | `h1`, `h2`, panel/section headings (`.bok-phase-group-heading`, `.bok-rail-header`, `.bok-graph-table caption` already use it — this promotes the same rule to a global `h1`/`h2` default so every screen's title/section heading is consistent, not just those three call sites). |
| Data | IBM Plex Mono (`--font-ibm-plex-mono`, already loaded) | Numbers, check IDs, timestamps, code, table cells, CWE/taxonomy refs — unchanged in spirit (`.bok-numeric` already does this); the new `StatTileGrid`/`Sparkline` numbers use it too. |
| Body | Geist Sans (`--font-geist-sans`, already loaded) | Prose, form labels, button text, alert/copy text — unchanged, the existing `body` default. |

New scale (`:root` custom properties, `globals.css`):

```
--text-xs: 0.6875rem;   /* 11px */
--text-sm: 0.75rem;     /* 12px */
--text-base: 0.8125rem; /* 13px, current body-copy size */
--text-md: 0.875rem;    /* 14px */
--text-lg: 1rem;        /* 16px */
--text-xl: 1.125rem;    /* 18px */
--text-2xl: 1.375rem;   /* 22px */
--text-3xl: 1.75rem;    /* 28px */
```

Applied via a new global rule:

```css
h1, h2 {
  font-family: var(--font-newsreader), serif;
  font-weight: 600;
}
h1 { font-size: var(--text-2xl); }
h2 { font-size: var(--text-lg); }
```

(More specific existing rules — `.bok-phase-group-heading`, `.bok-rail-header`,
`.bok-graph-table caption` — keep their own `font-size` overrides; only the
family/weight default is new and they already matched it.)

## 4. Color & elevation tokens

Added to `:root` in `globals.css`, alongside the existing `--neutral-*` ramp
(both light and dark `@media`/`[data-theme]` blocks get matching values, same
pattern the file already follows for `--paper`/`--ink`/`--neutral-*`):

```
--surface-0: var(--paper);         /* page background, unchanged */
--surface-1: var(--neutral-100);   /* panel/card background */
--surface-2: var(--neutral-150);   /* nested/hover state */
--border-subtle: var(--neutral-150);
```

**Corrected during implementation (Task 2, 2026-09-20):** the values above
were originally specified as `--neutral-50`/`--neutral-100`. In the light
theme, `--neutral-50` is byte-identical to `--paper`
(`oklch(0.985 0.004 85)`, `globals.css`'s existing token block) — using it
for `--surface-1` would have made panels indistinguishable from the page
background, a no-op for the entire elevation feature this section
describes. The ramp was shifted up one step (`--neutral-100`/`--neutral-150`)
and verified to produce a correctly-ordered, visible lightness step in all
three theme blocks (light `:root`, dark `@media`, `:root[data-theme="dark"]`).

Panel treatment (applied to `.bok-phase-group`, `.bok-graph`, `.bok-evidence`,
`.bok-rail`, `.bok-quota-item`, and the new `StatTileGrid` wrapper):

```css
background: var(--surface-1);
border: 1px solid var(--border-subtle);
box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
```

Severity chip background, added to `.bok-severity-badge` (glyph + label
untouched):

```css
background: color-mix(in oklch, var(--severity-critical) 12%, transparent);
/* one rule per severity, keyed the same way `.bok-severity-critical` etc. already are */
```

Re-verify `web/tests/tokens.spec.ts` and `web/tests/a11y.spec.ts` (axe
`color-contrast`) after the chip background change — the existing severity
ramp was already tuned once specifically to clear the 4.5:1 text-contrast
floor (see the `globals.css:34-42` comment); a background tint must not
regress that.

## 5. New data-visualization components (`web/src/lib/_bok-viz.tsx`)

New file, same pattern as `_bok-ui.tsx` (a `bok-ui` stand-in, deleted when the
real package ships) — kept separate because `_bok-ui.tsx` is already 1000+
lines and these components are a distinct, decorative-only layer with no
shared state or props with the rest of the library.

### 5.1 `StatTileGrid`
4-across tile row, tabular-mono numbers, severity-tinted accents.

```ts
export interface StatTile {
  label: string;
  value: number | string;
  tone?: "critical" | "high" | "medium" | "low" | "neutral";
}
export interface StatTileGridProps {
  tiles: StatTile[]; // rendered in order, wraps below 4 on narrow viewports
}
```
Each tile: `aria-hidden="true"` (the real numbers already exist as
accessible text elsewhere on the page — `ConformanceStrip`, the findings
table, the live-scan status region); no new tab stops, no new ARIA role.

**Consumers:**
- Findings screen: `[Critical, High, Medium, Low]` counts derived from the
  existing `findings` array (`toRow`'s `severity` field), placed between
  `<h1>Findings</h1>` and `ConformanceStrip`.
- Live-scan screen: `[Findings, Passed, Skipped, Coverage]` — `Findings` =
  `findingsCount` (already fetched) or `"—"` while unknown, `Passed`/
  `Skipped` from the existing `rows`/`terminalEvent.skipped` counts,
  `Coverage` = `passed / progress.total` as a percentage once `progress` is
  known, else `"—"`. Placed directly under the existing progress `<p
  role="status">`.

### 5.2 `Sparkline`
Thin inline SVG polyline, amber (`--accent`) stroke.

```ts
export interface SparklineProps {
  points: number[]; // chronological; fewer than 2 renders null (D6)
  label: string;    // accessible label for the aria-hidden svg's sibling text
}
```
Renders `null` when `points.length < 2` — no synthetic flat line.

**Consumer:** Drift screen header, next to the existing `RunTimeline`. The
existing `scans.length < 2` gate (`drift/page.tsx:88`) already means the
sparkline's own render path only ever sees ≥2 points once reached, so no
extra gating is needed at the call site beyond passing the data through.
**Data-availability note:** the live `GET /api/scans/{id}/drift` response
(`DriftResponse.scans: DriftScanSummary[]`, `web/src/lib/api.ts:238-244`)
carries no per-scan finding count today — only id/timestamp fields. This
plan wires the sparkline against the `?fixture=` fixtures
(`web/app/scans/[id]/drift/fixtures.ts`, extended with a `findingsCount` per
scan) and passes an empty array for the live path, which `Sparkline`
already renders as nothing (D6) — never a fabricated count. Adding a real
per-scan finding-count field to the backend response is a separate,
Python-side follow-up (`agent_perimeter/api/drift.py`), out of scope here.

### 5.3 `SeverityDistributionBar`
Horizontal stacked bar (critical/high/medium/low segments), a compact
alternative to `StatTileGrid` for narrow layouts.

**Consumer:** deferred. Its only planned use is the print/census report,
which is rendered by `agent_perimeter/report/templates/{report,census}.html.j2`
— a Python/Jinja subsystem with its own stylesheet
(`agent_perimeter/report/templates/report.css`), not `web/app/**`. Building
a React component with no call site in this codebase would be a
half-finished implementation (CLAUDE.md: "no half-finished
implementations"). **Not built in this plan** — tracked as a follow-up plan
scoped to `agent_perimeter/report/templates/*`.

## 6. Rollout order

1. Typography scale + global `h1`/`h2` rule (pure CSS, `tokens.spec.ts` +
   visual check).
2. Elevation/surface tokens + panel treatment + severity chip backgrounds,
   re-run `tokens.spec.ts` and `a11y.spec.ts` contrast checks.
3. `StatTileGrid` in `_bok-viz.tsx`, wired into the Findings screen.
4. `StatTileGrid` reused on the Live-scan screen.
5. `Sparkline` in `_bok-viz.tsx`, wired into the Drift screen with extended
   fixtures.
6. Full `a11y.spec.ts` + `tokens.spec.ts` + targeted screen suites re-run
   after each step, per the existing project testing bar.

## 7. Out of scope / follow-ups

- `SeverityDistributionBar` + `report.html`/`census.html` Jinja template
  wiring (§5.3) — separate plan, Python/Jinja subsystem.
- Full typography audit of every hardcoded `em`/`rem` font-size in
  `globals.css` — this pass only touches headings and new components (D2).
- Per-scan finding-count field on `GET /api/scans/{id}/drift` — separate
  backend plan; the fixture path is sufficient to ship the `Sparkline`
  component honestly today (§5.2).
