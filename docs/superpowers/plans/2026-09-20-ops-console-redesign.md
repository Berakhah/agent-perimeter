# Data-Dense Ops Console (Serif Accent) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the five Next.js screens a typography system with real
hierarchy (Newsreader headings, IBM Plex Mono data, Geist Sans body), a
layered elevation model (surface tokens + hairline panel borders instead of
one flat background), and two new decorative data-visualization components
(`StatTileGrid`, `Sparkline`) wired into the Findings, Live-scan, and Drift
screens.

**Architecture:** Pure CSS custom-property additions to
`web/app/globals.css` (typography scale, surface/elevation tokens, severity
chip backgrounds) plus a new component file `web/src/lib/_bok-viz.tsx`
(same "bok-ui stand-in" pattern as the existing `_bok-ui.tsx`) holding the
two new components. No new dependencies, no changes to `--paper`/`--ink`/
`--accent`/severity-hue values, no changes to any Python/backend code.

**Tech Stack:** Next.js 15 (App Router, Client Components), Tailwind v4
(imported but not used via utility classes in this codebase — all styling is
hand-written `.bok-*` CSS in `globals.css`), Playwright + `@axe-core/playwright`
for testing (no unit-test harness exists; every RED/GREEN cycle in this
plan is a Playwright test against a real route).

**Spec:** `docs/superpowers/specs/2026-09-20-ops-console-design.md`

## Global Constraints

- Never change `--paper`, `--ink`, or `--accent` values (spec §0, 00 §5.2 — pinned).
- Severity/provenance color is never the sole encoder — every colored
  element keeps its glyph + label (00 §5.2, spec D4).
- No new runtime dependencies — hand-rolled SVG/CSS only (spec D5, CLAUDE.md
  $0-recurring-cost / Apache-MIT-only dependency floor).
- Decorative visualizations get `aria-hidden="true"`; the real numbers must
  already exist as accessible text elsewhere on the page (spec §5.1/5.2).
- No fabricated data: an unavailable metric renders `"—"` or nothing, never
  a placeholder number or flat line (CLAUDE.md copy rules, spec D6).
- `web/tests/tokens.spec.ts` and `web/tests/a11y.spec.ts` (axe
  `wcag2a`/`wcag2aa`/`wcag21aa`/`wcag22aa`, "serious"/"critical" only) must
  keep passing after every task — these are the project's existing
  regression gates for exactly the properties this plan touches (contrast,
  color-independence, tabular numerals).
- Coverage floor 75% is a whole-project figure (CLAUDE.md); this plan does
  not lower it — every new component ships with a Playwright test that
  exercises its real render path.

---

## Task 1: Typography scale + global heading rule

**Files:**
- Modify: `web/app/globals.css` (add `--text-*` tokens to `:root`, add a new
  `h1, h2` rule)
- Test: `web/tests/tokens.spec.ts` (add a new test)

**Interfaces:**
- Produces: CSS custom properties `--text-xs` through `--text-3xl`,
  available to every later task's CSS. No JS/TS interface.

- [ ] **Step 1: Write the failing test**

Add to `web/tests/tokens.spec.ts`:

```ts
test("headings use the display typeface and scale", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const h1 = page.getByRole("heading", { level: 1 });
  await expect(h1).toHaveCSS("font-family", /Newsreader/);
  const fontSize = await h1.evaluate((el) => getComputedStyle(el).fontSize);
  expect(fontSize).toBe("22px");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx playwright test tokens.spec.ts -g "headings use the display typeface"`
Expected: FAIL — `h1`'s computed `font-family` is currently the inherited
Geist Sans body font (no `h1`/`h2` rule exists in `globals.css` today), and
its font-size is the browser UA default (not 22px).

- [ ] **Step 3: Write minimal implementation**

In `web/app/globals.css`, add to the existing `:root` block (after the
`--density-gap` line, i.e. right before the closing `}` of the first
`:root` rule):

```css
  /* Type scale (spec 2026-09-20-ops-console-design.md §3) -- headings and
     the new StatTileGrid/Sparkline components step through this; existing
     hardcoded em/rem sizes elsewhere are unchanged (not a full audit). */
  --text-xs: 0.6875rem;
  --text-sm: 0.75rem;
  --text-base: 0.8125rem;
  --text-md: 0.875rem;
  --text-lg: 1rem;
  --text-xl: 1.125rem;
  --text-2xl: 1.375rem;
  --text-3xl: 1.75rem;
```

Then add a new rule directly after the closing `}` of the `@theme inline`
block (before the first `@media (prefers-color-scheme: dark)` block):

```css
/* Two-voice typography (spec §3): Newsreader for titles/section heads,
   IBM Plex Mono for data (unchanged, .bok-numeric), Geist Sans for body
   (unchanged, `body` rule below). More specific existing rules --
   .bok-phase-group-heading, .bok-rail-header, .bok-graph-table caption --
   already set this family; this is the new default for every other h1/h2. */
h1,
h2 {
  font-family: var(--font-newsreader), serif;
  font-weight: 600;
}
h1 {
  font-size: var(--text-2xl);
}
h2 {
  font-size: var(--text-lg);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx playwright test tokens.spec.ts -g "headings use the display typeface"`
Expected: PASS

- [ ] **Step 5: Run the full existing token + a11y suites to check for regressions**

Run: `cd web && npx playwright test tokens.spec.ts a11y.spec.ts`
Expected: all PASS (the new `h1`/`h2` rule must not change any existing
axe contrast/focus-ring results — Newsreader at `--text-2xl`/`--text-lg`
on `var(--ink)` over `var(--paper)` has the same contrast ratio as the
existing body text since only the family/size changed, not the color).

- [ ] **Step 6: Commit**

```bash
git add web/app/globals.css web/tests/tokens.spec.ts
git commit -m "feat(web): add type scale tokens and serif heading voice"
```

---

## Task 2: Elevation/surface tokens + panel treatment + severity chip backgrounds

**Files:**
- Modify: `web/app/globals.css` (add `--surface-*`/`--border-subtle` tokens
  to all three token blocks — light `:root`, dark `@media`, dark
  `:root[data-theme="dark"]` — plus panel-rule updates and severity-badge
  background rules)
- Test: `web/tests/tokens.spec.ts` (add new tests), `web/tests/a11y.spec.ts`
  (existing suite re-run, no new test needed — it already screenshots/audits
  every screen this touches)

**Interfaces:**
- Consumes: `--neutral-50`, `--neutral-100`, `--neutral-150`,
  `--severity-critical/high/medium/low/info` (existing, `globals.css:18-47`).
- Produces: `--surface-0`, `--surface-1`, `--surface-2`, `--border-subtle`
  custom properties, and a `background` declaration on `.bok-severity-badge`
  (available to any later task's CSS).

- [ ] **Step 1: Write the failing test**

Add to `web/tests/tokens.spec.ts`:

```ts
test("panels are visually layered above the page background", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  const panel = page.locator(".bok-phase-group").first();
  await expect(panel).toBeVisible();
  const [panelBg, pageBg] = await Promise.all([
    panel.evaluate((el) => getComputedStyle(el).backgroundColor),
    page.evaluate(() => getComputedStyle(document.body).backgroundColor),
  ]);
  expect(panelBg).not.toBe(pageBg);
  await expect(panel).toHaveCSS("border-width", "1px");
});

test("severity badges carry a tinted background, not colour-alone", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const badge = page.getByTestId("severity-badge").first();
  const bg = await badge.evaluate((el) => getComputedStyle(el).backgroundColor);
  expect(bg).not.toBe("rgba(0, 0, 0, 0)");
  // Colour-independence is unchanged: glyph + label still present.
  await expect(badge).toHaveAttribute("data-glyph", /.+/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx playwright test tokens.spec.ts -g "panels are visually layered|tinted background"`
Expected: FAIL — `.bok-phase-group` currently has no `background`
declaration (transparent, same as `body`) and `.bok-severity-badge` has no
`background` declaration today (`globals.css:304-319`).

- [ ] **Step 3: Write minimal implementation**

In `web/app/globals.css`, add to the light `:root` block (same place as
Task 1's `--text-*` additions):

```css
  /* Elevation surfaces (spec §4) -- lightness steps, not shadows (shadows
     read poorly on the dark theme's near-black background). */
  --surface-0: var(--paper);
  --surface-1: var(--neutral-50);
  --surface-2: var(--neutral-100);
  --border-subtle: var(--neutral-150);
```

Add the same four lines (with the same variable names — they resolve
correctly because `--neutral-*`/`--paper` are already redefined per-theme)
to both the `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { ... } }`
block and the `:root[data-theme="dark"] { ... }` block, immediately after
their existing `--neutral-950` line in each.

Then add a shared panel treatment. Replace each of these existing selector
blocks' border declarations by adding `background` and `box-shadow` (do not
remove any existing declaration in the block, only add these two):

- `.bok-phase-group` (`globals.css:699-703`)
- `.bok-graph` — actually `.bok-graph-canvas` already has a background; add
  the treatment to `.bok-graph` (`globals.css:786-791`) instead, since that's
  the panel wrapper
- `.bok-evidence` (`globals.css:387-394`)
- `.bok-quota-item` (`globals.css:433-440`)

For each, add:

```css
background: var(--surface-1);
box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
```

(`.bok-phase-group`, `.bok-graph-canvas`, `.bok-evidence`, and
`.bok-quota-item` all already declare a 1px border — leave those as-is,
they already satisfy the "hairline border" requirement; only add the two
new declarations above to each.)

Then add severity-tinted chip backgrounds. In `.bok-severity-badge`
(`globals.css:304-319`), the per-severity color rules
(`.bok-severity-critical` etc., lines 320-334) currently set `color` only.
Add a `background` line to each:

```css
.bok-severity-critical {
  color: var(--severity-critical);
  background: color-mix(in oklch, var(--severity-critical) 12%, transparent);
}
.bok-severity-high {
  color: var(--severity-high);
  background: color-mix(in oklch, var(--severity-high) 12%, transparent);
}
.bok-severity-medium {
  color: var(--severity-medium);
  background: color-mix(in oklch, var(--severity-medium) 12%, transparent);
}
.bok-severity-low {
  color: var(--severity-low);
  background: color-mix(in oklch, var(--severity-low) 12%, transparent);
}
.bok-severity-info {
  color: var(--severity-info);
  background: color-mix(in oklch, var(--severity-info) 12%, transparent);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx playwright test tokens.spec.ts -g "panels are visually layered|tinted background"`
Expected: PASS

- [ ] **Step 5: Re-run the full a11y suite to verify no contrast regression**

Run: `cd web && npx playwright test a11y.spec.ts`
Expected: all PASS. If any `color-contrast` violation appears on a severity
badge, lower the `color-mix` percentage (try 8% before reverting) — the
badge's `color` (text) contrast against `--paper` is unaffected by an
added *background* tint since the badge's own background, not the page's,
is what changed; only if the badge text sits directly on its own tinted
background (it does — `color` on `background`) does this need re-checking,
which is exactly what this step verifies.

- [ ] **Step 6: Commit**

```bash
git add web/app/globals.css web/tests/tokens.spec.ts
git commit -m "feat(web): add elevation surface tokens and severity chip backgrounds"
```

---

## Task 3: `StatTileGrid` component, wired into the Findings screen

**Files:**
- Create: `web/src/lib/_bok-viz.tsx`
- Modify: `web/app/scans/[id]/findings/page.tsx`
- Modify: `web/app/globals.css` (new `.bok-stat-tile-grid` rules)
- Test: `web/tests/findings.spec.ts` (add a new test)

**Interfaces:**
- Produces (consumed by Task 4):
  ```ts
  export interface StatTile {
    label: string;
    value: number | string;
    tone?: "critical" | "high" | "medium" | "low" | "neutral";
  }
  export interface StatTileGridProps {
    tiles: StatTile[];
  }
  export function StatTileGrid(props: StatTileGridProps): JSX.Element;
  ```

- [ ] **Step 1: Write the failing test**

Add to `web/tests/findings.spec.ts`:

```ts
test("findings screen shows a severity stat tile grid backed by accessible counts", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const grid = page.getByTestId("stat-tile-grid");
  await expect(grid).toBeVisible();
  await expect(grid).toHaveAttribute("aria-hidden", "true");
  const criticalTile = grid.getByTestId("stat-tile-critical");
  const criticalCount = await criticalTile.getByTestId("stat-tile-value").innerText();
  // The tile is decorative -- the same count must exist as accessible text
  // via the real severity badges already rendered in the table.
  const badgeCount = await page.getByTestId("severity-badge").filter({ hasText: "Critical" }).count();
  expect(Number(criticalCount)).toBe(badgeCount);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx playwright test findings.spec.ts -g "severity stat tile grid"`
Expected: FAIL — no `stat-tile-grid` testid exists anywhere in the app yet.

- [ ] **Step 3: Write minimal implementation**

Create `web/src/lib/_bok-viz.tsx`:

```tsx
"use client";

/**
 * Decorative data-visualization companions to `_bok-ui.tsx` (see that
 * file's header comment for the `bok-ui` stand-in rationale -- this is the
 * same kind of stand-in, kept in a separate file because it's a distinct,
 * decorative-only layer with no shared state or props with the rest of the
 * library). Every component here is `aria-hidden="true"`: the numbers it
 * renders already exist as accessible text elsewhere on the page (spec
 * `docs/superpowers/specs/2026-09-20-ops-console-design.md` §5).
 */

export type StatTileTone = "critical" | "high" | "medium" | "low" | "neutral";

export interface StatTile {
  label: string;
  value: number | string;
  tone?: StatTileTone;
}

export interface StatTileGridProps {
  tiles: StatTile[];
}

/** 4-across tile row (wraps below 4 on narrow viewports); tabular-mono numbers, severity-tinted accents. */
export function StatTileGrid({ tiles }: StatTileGridProps) {
  return (
    <div className="bok-stat-tile-grid" data-testid="stat-tile-grid" aria-hidden="true">
      {tiles.map((tile) => (
        <div
          key={tile.label}
          className={`bok-stat-tile bok-stat-tile-${tile.tone ?? "neutral"}`}
          data-testid={`stat-tile-${tile.label.toLowerCase()}`}
        >
          <span className="bok-stat-tile-value bok-numeric" data-testid="stat-tile-value">
            {tile.value}
          </span>
          <span className="bok-stat-tile-label">{tile.label}</span>
        </div>
      ))}
    </div>
  );
}
```

Add to `web/app/globals.css`, at the end of the file:

```css
/* StatTileGrid -- decorative severity/coverage summary (spec §5.1). */
.bok-stat-tile-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--density-gap);
  margin-bottom: calc(var(--density-gap) * 2);
}
@media (max-width: 480px) {
  .bok-stat-tile-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
.bok-stat-tile {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: var(--density-cell-y) var(--density-cell-x);
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-control);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}
.bok-stat-tile-value {
  font-size: var(--text-2xl);
  font-weight: 600;
}
.bok-stat-tile-label {
  font-size: var(--text-sm);
  color: var(--neutral-600);
}
.bok-stat-tile-critical .bok-stat-tile-value {
  color: var(--severity-critical);
}
.bok-stat-tile-high .bok-stat-tile-value {
  color: var(--severity-high);
}
.bok-stat-tile-medium .bok-stat-tile-value {
  color: var(--severity-medium);
}
.bok-stat-tile-low .bok-stat-tile-value {
  color: var(--severity-low);
}
```

Modify `web/app/scans/[id]/findings/page.tsx`: add the import and compute
severity counts from the existing `findings` array, then render the grid.

Add to the imports at the top:

```ts
import { StatTileGrid } from "@/src/lib/_bok-viz";
```

Add after the `gapsCount` `useMemo` (after line 184's closing `);`):

```ts
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (f.severity in counts) counts[f.severity as keyof typeof counts] += 1;
    }
    return counts;
  }, [findings]);
```

Then in the JSX, insert the grid right after `<h1>Findings</h1>` and before
`<ConformanceStrip`:

```tsx
      <StatTileGrid
        tiles={[
          { label: "Critical", value: severityCounts.critical, tone: "critical" },
          { label: "High", value: severityCounts.high, tone: "high" },
          { label: "Medium", value: severityCounts.medium, tone: "medium" },
          { label: "Low", value: severityCounts.low, tone: "low" },
        ]}
      />
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx playwright test findings.spec.ts -g "severity stat tile grid"`
Expected: PASS

- [ ] **Step 5: Run the full findings + a11y suites to check for regressions**

Run: `cd web && npx playwright test findings.spec.ts a11y.spec.ts tokens.spec.ts`
Expected: all PASS. The grid is `aria-hidden="true"` so it must not appear
in the a11y suite's Tab-reachability count or axe's accessible-name checks.

- [ ] **Step 6: Commit**

```bash
git add web/src/lib/_bok-viz.tsx web/app/scans/\[id\]/findings/page.tsx web/app/globals.css web/tests/findings.spec.ts
git commit -m "feat(web): add StatTileGrid, wire into findings screen"
```

---

## Task 4: Reuse `StatTileGrid` on the Live-scan screen

**Files:**
- Modify: `web/app/scans/[id]/page.tsx`
- Test: `web/tests/live-scan.spec.ts` (add a new test)

**Interfaces:**
- Consumes: `StatTileGrid`, `StatTile` from `@/src/lib/_bok-viz` (Task 3).

- [ ] **Step 1: Write the failing test**

Add to `web/tests/live-scan.spec.ts`:

```ts
test("live-scan screen shows a findings/passed/skipped/coverage stat tile grid", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.getByRole("status", { name: /checks complete|starting scan/i })).toBeVisible();
  await expect
    .poll(async () => page.getByTestId("stat-tile-grid").count())
    .toBeGreaterThan(0);
  const grid = page.getByTestId("stat-tile-grid");
  await expect(grid).toHaveAttribute("aria-hidden", "true");
  await expect(grid.getByTestId("stat-tile-passed")).toBeVisible();
  await expect(grid.getByTestId("stat-tile-skipped")).toBeVisible();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx playwright test live-scan.spec.ts -g "findings/passed/skipped/coverage"`
Expected: FAIL — the live-scan screen renders no `stat-tile-grid` yet.

- [ ] **Step 3: Write minimal implementation**

In `web/app/scans/[id]/page.tsx`, add the import:

```ts
import { StatTileGrid } from "@/src/lib/_bok-viz";
```

Add derived counts near the existing `hasPending`/`skippedCount` `const`s
(after line 202):

```ts
  const passedCount = rows.filter((r) => r.status === "passed").length;
  const coverage =
    progress && progress.total > 0 ? `${Math.round((passedCount / progress.total) * 100)}%` : "—";
```

Insert the grid in the JSX right after the existing progress/terminal
status block and before the `connectionError` block (after the closing
`)}` at line 250, before line 252's `{connectionError && (`):

```tsx
      <StatTileGrid
        tiles={[
          { label: "Findings", value: typeof findingsCount === "number" ? findingsCount : "—" },
          { label: "Passed", value: passedCount },
          { label: "Skipped", value: skippedCount, tone: skippedCount > 0 ? "medium" : "neutral" },
          { label: "Coverage", value: coverage },
        ]}
      />
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx playwright test live-scan.spec.ts -g "findings/passed/skipped/coverage"`
Expected: PASS

- [ ] **Step 5: Run the full live-scan + a11y suites to check for regressions**

Run: `cd web && npx playwright test live-scan.spec.ts a11y.spec.ts`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add web/app/scans/\[id\]/page.tsx web/tests/live-scan.spec.ts
git commit -m "feat(web): reuse StatTileGrid on the live-scan screen"
```

---

## Task 5: `Sparkline` component, wired into the Drift screen

**Files:**
- Modify: `web/src/lib/_bok-viz.tsx` (add `Sparkline`)
- Modify: `web/app/scans/[id]/drift/fixtures.ts` (add `findingsCount` per scan)
- Modify: `web/app/scans/[id]/drift/page.tsx`
- Modify: `web/app/globals.css` (new `.bok-sparkline` rules)
- Test: `web/tests/drift.spec.ts` (add new tests)

**Interfaces:**
- Produces:
  ```ts
  export interface SparklineProps {
    points: number[];
    label: string;
  }
  export function Sparkline(props: SparklineProps): JSX.Element | null;
  ```

- [ ] **Step 1: Write the failing test**

Add to `web/tests/drift.spec.ts`:

```ts
test("drift screen shows a findings-over-time sparkline when scan history exists", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  await expect(page.getByTestId("findings-sparkline")).toBeVisible();
  await expect(page.getByTestId("findings-sparkline")).toHaveAttribute("aria-hidden", "true");
});

test("drift screen shows no sparkline for a single scan (no fabricated flat line)", async ({ page }) => {
  await page.goto("/scans/1/drift?fixture=single-scan");
  // single-scan already renders the "not enough scan history" EmptyState,
  // before any sparkline call site is reached.
  await expect(page.getByTestId("findings-sparkline")).toHaveCount(0);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx playwright test drift.spec.ts -g "sparkline"`
Expected: first test FAILs (no `findings-sparkline` testid exists yet);
second test currently PASSes vacuously (nothing renders at all today) — it
becomes a real regression guard once Step 3 lands.

- [ ] **Step 3: Write minimal implementation**

Add to `web/src/lib/_bok-viz.tsx`:

```tsx
export interface SparklineProps {
  points: number[];
  label: string;
}

const SPARKLINE_WIDTH = 120;
const SPARKLINE_HEIGHT = 28;

/** Thin amber polyline over recent finding counts. Renders nothing for fewer than 2 points -- never a fabricated flat line (spec D6). */
export function Sparkline({ points, label }: SparklineProps) {
  if (points.length < 2) return null;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const coords = points
    .map((value, i) => {
      const x = (i / (points.length - 1)) * SPARKLINE_WIDTH;
      const y = SPARKLINE_HEIGHT - ((value - min) / range) * SPARKLINE_HEIGHT;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      className="bok-sparkline"
      data-testid="findings-sparkline"
      aria-hidden="true"
      viewBox={`0 0 ${SPARKLINE_WIDTH} ${SPARKLINE_HEIGHT}`}
      role="img"
    >
      <title>{label}</title>
      <polyline points={coords} fill="none" stroke="var(--accent)" strokeWidth="1.5" />
    </svg>
  );
}
```

Add to `web/app/globals.css`, at the end of the file:

```css
/* Sparkline -- decorative findings-over-time trend (spec §5.2). */
.bok-sparkline {
  width: 120px;
  height: 28px;
  overflow: visible;
}
```

Modify `web/app/scans/[id]/drift/fixtures.ts`: add `findingsCount` to
`DriftScan` and to both fixtures' scans:

```ts
export interface DriftScan {
  id: string;
  /** ISO 8601 timestamp -- absolute dates only, this is an audit artifact. */
  startedAt: string;
  /** Total findings from this scan -- drives the Sparkline (spec §5.2). */
  findingsCount: number;
}
```

```ts
  "single-scan": {
    target: "demo-mcp-server",
    scans: [{ id: "scan-1", startedAt: "2026-08-20T09:00:00Z", findingsCount: 3 }],
    driftedTools: [],
  },
  "changed-description": {
    target: "demo-mcp-server",
    scans: [
      { id: "scan-1", startedAt: "2026-08-20T09:00:00Z", findingsCount: 3 },
      { id: "scan-2", startedAt: "2026-09-03T14:30:00Z", findingsCount: 5 },
    ],
```

Modify `web/app/scans/[id]/drift/page.tsx`: add the import and pass
`findingsCount` through the existing `scans` mapping, then render the
sparkline.

Add to the imports:

```ts
import { Sparkline } from "@/src/lib/_bok-viz";
```

Change line 60's `scans` derivation to carry the count through (the live
path has no such field yet per the spec's data-availability note, so it
defaults to `0` there — never fabricated, just absent, and `Sparkline`'s
own `< 2 points` guard combined with the existing `scans.length < 2` page
gate means the live path's all-zero counts are never actually rendered
today; this is the documented, deliberate gap, not a bug):

```ts
  const scans =
    data?.scans ?? (live?.scans ?? []).map((s) => ({ id: s.id, startedAt: s.started_at, findingsCount: 0 }));
```

Insert the sparkline in the JSX right after `<RunTimeline events={timelineEvents} />`
(after line 113):

```tsx
      <Sparkline
        points={scans
          .slice()
          .sort((a, b) => a.startedAt.localeCompare(b.startedAt))
          .map((s) => s.findingsCount)}
        label={`Findings per scan, ${target}`}
      />
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx playwright test drift.spec.ts -g "sparkline"`
Expected: both PASS

- [ ] **Step 5: Run the full drift + a11y + tokens suites to check for regressions**

Run: `cd web && npx playwright test drift.spec.ts a11y.spec.ts tokens.spec.ts`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add web/src/lib/_bok-viz.tsx web/app/scans/\[id\]/drift/fixtures.ts web/app/scans/\[id\]/drift/page.tsx web/app/globals.css web/tests/drift.spec.ts
git commit -m "feat(web): add Sparkline, wire into drift screen"
```

---

## Task 6: Full suite verification and design record

**Files:**
- Modify: `docs/superpowers/specs/2026-09-20-ops-console-design.md` (status line)
- Create: none (documentation update only)

**Interfaces:** none — verification task.

- [ ] **Step 1: Run the complete Playwright suite**

Run: `cd web && npx playwright test`
Expected: all tests PASS (the existing 90+ tests plus every test added in
Tasks 1-5).

- [ ] **Step 2: Run lint and type-check**

Run: `cd web && npm run lint && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Manually verify in a browser**

Start the dev server (`cd web && npm run dev`) and visually check, per the
spec's rollout order (§6):
- `/` and `/scans/1?fixture=streaming` — h1 renders in Newsreader at the new
  scale; live-scan stat tile grid appears once the terminal frame is reached.
- `/scans/1/findings?fixture=mixed` — stat tile grid above the conformance
  strip; severity badges show a tinted background at all four severities.
- `/scans/2/drift?fixture=changed-description` — sparkline renders next to
  the timeline; `/scans/1/drift?fixture=single-scan` shows no sparkline.
- `/scans/1/graph?fixture=deputy` — no regression to the existing graph
  panel's border/background (Task 2's `.bok-graph` change).

- [ ] **Step 4: Update the spec's status line**

Change `docs/superpowers/specs/2026-09-20-ops-console-design.md` line 4 from:

```
**Status:** brainstormed, plan pending execution
```

to:

```
**Status:** implemented <today's date> (plan `docs/superpowers/plans/2026-09-20-ops-console-redesign.md`)
```

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-09-20-ops-console-design.md
git commit -m "docs(spec): mark ops console redesign implemented"
```

---

## Self-review notes

- **Spec coverage:** §3 (typography) → Task 1. §4 (elevation/severity
  chips) → Task 2. §5.1 (`StatTileGrid`) → Tasks 3-4. §5.2 (`Sparkline`) →
  Task 5. §5.3 (`SeverityDistributionBar`) and §7 (follow-ups) → explicitly
  deferred, not silently dropped (out of scope per spec, separate
  Python/Jinja subsystem). §6 (rollout order) → task ordering matches.
- **Type consistency:** `StatTile`/`StatTileGridProps` (Task 3) are reused
  unchanged in Task 4. `SparklineProps` (Task 5) matches the spec's §5.2
  interface exactly. `DriftScan.findingsCount` (Task 5) is added once and
  consumed consistently in both the fixtures file and `page.tsx`.
