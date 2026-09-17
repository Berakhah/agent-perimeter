# Web UI Visual Polish + Motion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add purposeful micro-interactions (entrance, hover/focus, state-change transitions) and spacing polish to the five Next.js screens without changing a single design-token value, and prove every animation degrades to its legible end state under `prefers-reduced-motion`.

**Architecture:** One shared presets module (`web/src/lib/motion.ts`) wraps `motion`'s `useReducedMotion()` so every JS-driven entrance is a one-line hook call that already handles reduced motion, stagger capping, and a `data-entered` attribute tests can query. Simple hover/focus/state transitions stay in `globals.css` (the existing global reduced-motion rule at `globals.css:204-209` covers those for free). Each screen is one task; each task's RED test asserts an *end state* (attribute/class/computed style), never an animation's visual path, plus one reduced-motion test asserting the same end state is reached with a non-retrying assertion.

**Tech Stack:** Next.js 15.5 · React 19.1 · `motion` 13.4 (MIT, `import from "motion/react"`) · Tailwind 4 with hand-written `.bok-*` CSS in `web/app/globals.css` · Playwright 1.62 (`npx playwright test` from `web/`, auto-starts the dev server on :3100).

**Spec:** `docs/superpowers/specs/2026-09-16-web-ui-redesign-design.md` — read §4 (per-screen), §5 (binding rules), §6 (testing) before starting any task.

## Global Constraints

- **No token value changes** (spec D1, §7): no edit to any `--paper`, `--ink`, `--neutral-*`, `--accent`, `--severity-*`, `--provenance-*`, `--radius-*`, `--density-*`, or font-family declaration in `globals.css:13-63`. `tests/tokens.spec.ts` must stay green.
- **Only one new dependency: `motion`** (MIT). Nothing else. No GSAP (spec D4).
- **Every `motion` animation goes through `web/src/lib/motion.ts`** so `useReducedMotion()` is checked once, centrally — never a bare `<motion.x initial={…}>` in a screen file (spec §5 bullet 1).
- **Never animate a semantic-encoding property** (spec §5): edge `stroke-dasharray`/`stroke-dashoffset`, severity glyphs, provenance underline style. Animate `opacity`/`transform`/`stroke-opacity`/`background-color` only.
- **No overshoot/bounce easing anywhere** — `ease: "easeOut"` for every `motion` transition and `ease-out` for every CSS transition (spec D3/§5). The graph *may* use a slight settle; this plan chooses not to, for consistency.
- **Existing animations are sequenced, never stacked** (spec §5): Skeleton shimmer (`globals.css:632-645`), graph pulse ring (`globals.css:711-728`), ProvenanceRail item entrance (`globals.css:271`) — a new animation on the same element waits for them or is skipped.
- **Timings** (spec §2): hover/focus 150ms · state change 200ms · row/node reveal 300ms · edge reveal 400ms · stagger ≤40ms/item, total reveal capped at 400ms.
- **Copy rules** unchanged: this plan adds no user-facing strings. If a task finds it needs one, it states what happened and what to do, never apologises.
- **Density scale is `--density-cell-y` / `--density-cell-x` / `--density-gap`** (`globals.css:60-62`). The spec's §4.1 mention of a `--space-*` scale is a misnomer — there is no such scale; use `--density-*`.
- **`report.html` / `census.html` (port 4173) are untouched.** `a11y.spec.ts`'s `report` entries and `print.spec.ts` must stay green with zero edits.
- Run the whole suite from `web/`: `npx playwright test`. Single file: `npx playwright test tests/<file>.spec.ts`. Type-check + lint (CI runs both): `npx tsc --noEmit && npm run lint`.
- Commits: `feat(web): …` / `docs(spec): …`, ending with the attribution line from the session's system reminder.

---

## File structure

| File | Responsibility |
|---|---|
| `web/src/lib/motion.ts` (**create**) | The only place `motion/react`'s `useReducedMotion` is called. Exports timing constants, `staggerDelay()`, and three hooks — `useRiseIn`, `useScaleIn`, `useFadeIn` — each returning a spread-ready props object for a `motion.*` element (`initial`, `animate`, `transition`, `onAnimationComplete`, `data-entered`). |
| `web/app/components/MotionProvider.tsx` (**create**) | `"use client"` wrapper around `MotionConfig reducedMotion="user"` so the server-component `layout.tsx` can mount it. Belt-and-braces: even a bare `motion.*` that slipped past review has transforms disabled for reduced-motion viewers. |
| `web/app/layout.tsx` (modify) | Wrap `{children}` in `<MotionProvider>`. |
| `web/app/components/PhaseGroup.tsx` (modify) | Check rows become `motion.li` with `useRiseIn`. |
| `web/app/scans/[id]/page.tsx` (modify) | Terminal frame wrapped in a fade-in `motion.div` (incoming only). |
| `web/app/components/ScopeFileField.tsx` (modify) | `dragging` state → `data-dragging` attribute for the drag-over style. |
| `web/app/components/ModeSelector.tsx` (modify) | `data-unlocked` attribute on the fieldset (CSS transition hook). |
| `web/app/page.tsx` (modify) | Submit button gets `className="bok-submit"`, `data-submitting`, and a `<span className="bok-submit-label">`. |
| `web/src/lib/_bok-ui.tsx` (modify) | `FindingsTable`: rows render through a new internal `RevealRow` (`motion.tr` + per-row-id "already revealed" set); expanded row's content fades in. |
| `web/app/components/CapabilityGraph.tsx` (modify) | Node entrance (inner `motion.g` scale/opacity, sequenced before the pulse), edge fade-in (`motion.line`, staggered), hover/focus on a node marks connected/dimmed edges. |
| `web/app/globals.css` (modify) | All CSS hover/focus/state transitions and the diff highlight-in keyframe. |
| `web/app/print.css` (modify) | Kill all animation/transition under `@media print`. |
| `web/tests/live-scan.spec.ts`, `scan-setup.spec.ts`, `findings.spec.ts`, `graph.spec.ts`, `drift.spec.ts` (modify) | New end-state + reduced-motion tests appended to each. |
| `web/package.json`, `web/package-lock.json` (modify) | `motion` dependency. |

---

### Task 1: `motion` dependency, shared presets, and live-scan check-row entrance

**Files:**
- Modify: `web/package.json` (dependencies)
- Create: `web/src/lib/motion.ts`
- Create: `web/app/components/MotionProvider.tsx`
- Modify: `web/app/layout.tsx:44-58`
- Modify: `web/app/components/PhaseGroup.tsx:30-58`
- Test: `web/tests/live-scan.spec.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces (every later task relies on these exact names):
  ```ts
  // web/src/lib/motion.ts
  export const DURATION_S: { readonly hover: 0.15; readonly state: 0.2; readonly reveal: 0.3; readonly edge: 0.4 };
  export const STAGGER_S = 0.04;
  export const STAGGER_CAP_S = 0.4;
  export function staggerDelay(index: number): number;
  export interface EntranceOptions { index?: number; duration?: number; skip?: boolean }
  export interface EntranceProps {
    initial: false | EntranceTarget;
    animate: EntranceTarget;
    transition: Transition;            // from "motion/react"
    onAnimationComplete: () => void;
    "data-entered": "true" | "false";
  }
  export function useRiseIn(options?: EntranceOptions): EntranceProps;   // opacity 0→1, y 8→0
  export function useScaleIn(options?: EntranceOptions): EntranceProps;  // opacity 0→1, scale 0.95→1
  export function useFadeIn(options?: EntranceOptions): EntranceProps;   // opacity 0→1
  ```
  `data-entered` is `"true"` immediately when reduced motion is on or `skip` is true, otherwise flips to `"true"` from `onAnimationComplete`. Tests assert on this attribute.

- [ ] **Step 1: Install `motion`**

Run from `web/`:
```bash
npm install motion@^13.4.0
```
Expected: `package.json` gains `"motion": "^13.4.0"` under `dependencies`; lockfile updated. Confirm the licence in the installed package: `node -e "console.log(require('motion/package.json').license)"` → `MIT`.

- [ ] **Step 2: Write the failing tests**

Append to `web/tests/live-scan.spec.ts`:

```ts
// Web UI redesign (spec §4.2): each check row enters with a short rise-in.
// The test asserts the *end state* -- `data-entered="true"` is set from
// motion's onAnimationComplete -- never the animation's visual path.
test("check rows reach their entered state after streaming in", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  const first = page.getByTestId("check-row").first();
  await expect(first).toHaveAttribute("data-entered", "false");
  await expect(first).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(page.getByTestId("check-row").last()).toHaveAttribute("data-entered", "true", { timeout: 10_000 });
});

// Spec §5/§6: under reduced motion the end state is reached immediately.
// The non-retrying `getAttribute` (not `toHaveAttribute`) is the evidence --
// there is no window in which the row exists but is not yet entered.
test("reduced motion renders check rows already entered", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1?fixture=streaming");
  const first = page.getByTestId("check-row").first();
  await expect(first).toBeVisible();
  expect(await first.getAttribute("data-entered")).toBe("true");
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run from `web/`: `npx playwright test tests/live-scan.spec.ts`
Expected: the two new tests FAIL — `data-entered` attribute missing (`toHaveAttribute` times out; `getAttribute` returns `null`). All pre-existing tests in the file still pass.

- [ ] **Step 4: Create the presets module**

Create `web/src/lib/motion.ts`:

```ts
"use client";

/**
 * The single place `motion`'s `useReducedMotion()` is consulted (spec
 * 2026-09-16-web-ui-redesign §5, rule 1). Screens never write a bare
 * `<motion.x initial={...}>`; they spread one of the hooks below, which
 * already (a) render the final state on first paint under reduced motion,
 * (b) cap stagger so a long list never takes more than STAGGER_CAP_S to
 * settle, and (c) expose `data-entered` so a Playwright test can assert the
 * end state without inspecting pixels.
 *
 * Timings are the spec's §2 numbers: hover 150ms, state 200ms, reveal
 * 300ms, edge 400ms, ≤40ms/item stagger. Easing is always easeOut -- no
 * overshoot anywhere (spec D3).
 */
import { useReducedMotion, type Transition } from "motion/react";
import { useState } from "react";

export const DURATION_S = { hover: 0.15, state: 0.2, reveal: 0.3, edge: 0.4 } as const;
export const STAGGER_S = 0.04;
export const STAGGER_CAP_S = 0.4;

/** Per-item delay for the item at `index`, capped so the whole list settles inside STAGGER_CAP_S. */
export function staggerDelay(index: number): number {
  return Math.min(Math.max(index, 0) * STAGGER_S, STAGGER_CAP_S);
}

export interface EntranceTarget {
  opacity: number;
  y?: number;
  scale?: number;
}

export interface EntranceOptions {
  /** Position in the list, for stagger. Default 0. */
  index?: number;
  /** Seconds. Default DURATION_S.reveal. */
  duration?: number;
  /**
   * Render the end state with no animation even when motion is allowed --
   * FindingsTable uses this for a virtualizer remount of a row that has
   * already been revealed once (spec §4.3).
   */
  skip?: boolean;
}

export interface EntranceProps {
  initial: false | EntranceTarget;
  animate: EntranceTarget;
  transition: Transition;
  onAnimationComplete: () => void;
  "data-entered": "true" | "false";
}

function useEntrance(from: EntranceTarget, to: EntranceTarget, options: EntranceOptions): EntranceProps {
  // `null` only during SSR; every animated element on these screens is
  // client-rendered after a fetch/stream, so treating null as "not reduced"
  // never paints a reduced-motion viewer's content at opacity 0.
  const reduced = useReducedMotion() ?? false;
  const [entered, setEntered] = useState(false);
  const immediate = reduced || options.skip === true;
  return {
    initial: immediate ? false : from,
    animate: to,
    transition: immediate
      ? { duration: 0 }
      : { duration: options.duration ?? DURATION_S.reveal, ease: "easeOut", delay: staggerDelay(options.index ?? 0) },
    onAnimationComplete: () => setEntered(true),
    "data-entered": immediate || entered ? "true" : "false",
  };
}

/** Opacity 0→1 with an 8px rise. List rows (spec §4.2, §4.3). */
export function useRiseIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0, y: 8 }, { opacity: 1, y: 0 }, options);
}

/** Opacity 0→1 with scale 0.95→1. Graph nodes (spec §4.4). */
export function useScaleIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0, scale: 0.95 }, { opacity: 1, scale: 1 }, options);
}

/** Opacity only. Status-frame swaps and graph edges (spec §4.2, §4.4). */
export function useFadeIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0 }, { opacity: 1 }, { duration: DURATION_S.state, ...options });
}
```

- [ ] **Step 5: Create the provider and mount it in the layout**

Create `web/app/components/MotionProvider.tsx`:

```tsx
"use client";

/**
 * `MotionConfig reducedMotion="user"` disables transform/layout animations
 * for viewers who asked for reduced motion, app-wide. It is the safety net
 * under `src/lib/motion.ts` (which is the real reduced-motion contract:
 * final state on first paint), not a replacement for it -- MotionConfig
 * still lets opacity animate, which is not "immediately legible".
 * Separate file because `app/layout.tsx` is a server component and
 * MotionConfig needs a client boundary.
 */
import { MotionConfig } from "motion/react";
import type { ReactNode } from "react";

export function MotionProvider({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user">{children}</MotionConfig>;
}
```

Modify `web/app/layout.tsx`: add the import after the `"./print.css"` import:

```tsx
import { MotionProvider } from "./components/MotionProvider";
```

and change the body's `{children}` to:

```tsx
        <MotionProvider>{children}</MotionProvider>
```

- [ ] **Step 6: Animate the check rows**

Modify `web/app/components/PhaseGroup.tsx`. Add `"use client";` as the very first line of the file (it currently has none; `useRiseIn` is a hook). After the doc comment add:

```tsx
import { motion } from "motion/react";

import { useRiseIn } from "@/src/lib/motion";
```

Replace the `PhaseGroup` function body and add a `CheckRow` component:

```tsx
export function PhaseGroup({ phase, checks }: PhaseGroupProps) {
  const headingId = `phase-group-${phase}`;
  return (
    <section className="bok-phase-group" role="group" aria-labelledby={headingId}>
      <h2 id={headingId} className="bok-phase-group-heading">
        {phase}
      </h2>
      <ul className="bok-phase-group-list">
        {checks.map((check, index) => (
          <CheckRow key={check.checkId} check={check} index={index} />
        ))}
      </ul>
    </section>
  );
}

/**
 * One row, entering with the spec §4.2 rise-in. Rows normally arrive one at
 * a time over the stream, so `index` stagger rarely compounds; it matters
 * only when a batch lands in one render (e.g. the skipped rows the terminal
 * frame adds all at once).
 */
function CheckRow({ check, index }: { check: PhaseGroupCheck; index: number }) {
  const entrance = useRiseIn({ index });
  return (
    <motion.li
      {...entrance}
      data-testid="check-row"
      data-status={check.status}
      className={`bok-check-row bok-check-${check.status}`}
    >
      <span className="bok-numeric bok-check-id">{check.checkId}</span>
      {check.status === "skipped" ? (
        <span className="bok-check-detail">Skipped — {check.detail}</span>
      ) : (
        <span className="bok-check-detail">
          {check.status === "passed" ? "Passed" : "Errored"}
          {check.elapsedMs != null ? ` · ${check.elapsedMs}ms` : ""}
        </span>
      )}
    </motion.li>
  );
}
```

`index` here is the row's position *within its phase group*, which is what a user sees stagger across. It is deliberately not the global row index.

- [ ] **Step 7: Type-check, lint, run the tests**

Run from `web/`: `npx tsc --noEmit && npm run lint && npx playwright test tests/live-scan.spec.ts`
Expected: tsc clean, lint clean, all tests in the file PASS including the two new ones. If tsc complains that `"easeOut"` is not assignable to `Transition["ease"]`, change the `ease` value in `motion.ts` to the cubic-bezier array `[0, 0, 0.58, 1]` (which *is* CSS `ease-out`) — do not switch to any overshooting curve.

- [ ] **Step 8: Run the a11y matrix for this screen**

Run: `npx playwright test tests/a11y.spec.ts -g "live scan"`
Expected: all four `live scan` tests PASS (axe, keyboard, focus ring, 375px).

- [ ] **Step 9: Commit**

```bash
git add web/package.json web/package-lock.json web/src/lib/motion.ts web/app/components/MotionProvider.tsx web/app/layout.tsx web/app/components/PhaseGroup.tsx web/tests/live-scan.spec.ts
git commit -m "feat(web): motion presets + live-scan check-row entrance

Adds motion (MIT) behind a single presets module so useReducedMotion is
checked once; check rows rise in 300ms easeOut and expose data-entered
for end-state tests. Reduced motion renders rows entered on first paint."
```

---

### Task 2: Live-scan terminal-frame fade-in

**Files:**
- Modify: `web/app/scans/[id]/page.tsx:216-243`
- Test: `web/tests/live-scan.spec.ts`

**Interfaces:**
- Consumes: `useFadeIn` from `web/src/lib/motion.ts` (Task 1).
- Produces: a `data-testid="terminal-frame"` wrapper `<div>` around whichever terminal element renders (EmptyState / findings summary / unknown summary), carrying `data-entered`.

The invariant documented at `page.tsx:7-22` — exactly one `role="status"` announcer at a time — is preserved: the running `<p role="status">` unmounts on the same render the terminal frame mounts. Only the *incoming* element fades (spec §4.2); nothing keeps the outgoing element alive.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/live-scan.spec.ts`:

```ts
// Spec §4.2: the running→terminal swap cross-fades the incoming summary.
// Both role="status" sources must never coexist (page.tsx header comment),
// so only the incoming frame animates -- assert it reaches its end state
// and that the progress announcer is gone by then.
test("the terminal summary fades in and replaces the progress announcer", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  const frame = page.getByTestId("terminal-frame");
  await expect(frame).toHaveAttribute("data-entered", "true", { timeout: 10_000 });
  await expect(page.locator(".bok-scan-progress")).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: /findings/ })).toHaveCount(1);
});

test("reduced motion renders the terminal summary already entered", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1?fixture=streaming");
  const frame = page.getByTestId("terminal-frame");
  await expect(frame).toBeVisible({ timeout: 10_000 });
  expect(await frame.getAttribute("data-entered")).toBe("true");
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx playwright test tests/live-scan.spec.ts -g "terminal summary"`
Expected: both FAIL — no element with `data-testid="terminal-frame"`.

- [ ] **Step 3: Add the fade-in wrapper**

In `web/app/scans/[id]/page.tsx`, add imports (after the existing `@/src/lib/api` import):

```tsx
import { motion } from "motion/react";

import { useFadeIn } from "@/src/lib/motion";
```

Extend the existing `react` import line with `type ReactNode` (it currently imports `use, useEffect, useMemo, useState` — check the exact line and add `type ReactNode` to it).

Add this component at the bottom of the file:

```tsx
/**
 * Fades in whichever terminal element replaces the running progress
 * announcer (spec §4.2). A wrapper `div`, not a `motion.p`, so the three
 * terminal branches above keep their own role="status" elements untouched.
 * Mounting this is the same render that unmounts `.bok-scan-progress`, so
 * there is never a moment with two live regions.
 */
function TerminalFrame({ children }: { children: ReactNode }) {
  const fade = useFadeIn();
  return (
    <motion.div {...fade} data-testid="terminal-frame">
      {children}
    </motion.div>
  );
}
```

Then wrap the three terminal branches. The JSX from `{terminalEvent === null ? (` to its closing `)}` becomes:

```tsx
      {terminalEvent === null ? (
        <p role="status" aria-live="polite" className="bok-scan-progress">
          {progress ? `${progress.completed} of ${progress.total} checks complete` : "Starting scan…"}
        </p>
      ) : (
        <TerminalFrame>
          {fixture || findingsCount === 0 ? (
            // Fixture mode: none of the three canned scenarios represents an
            // unclean run, so this stays the existing, verified-clean copy.
            // Real mode: `findingsCount === 0` is the one case where "No
            // findings" is actually true.
            <EmptyState
              title="No findings for the checks that ran"
              description={
                skippedCount === 0
                  ? "0 checks skipped."
                  : `${skippedCount} check${skippedCount === 1 ? "" : "s"} skipped — see the skipped rows below for why.`
              }
            />
          ) : typeof findingsCount === "number" ? (
            <p data-testid="findings-summary" role="status" aria-live="polite">
              {findingsCount} finding{findingsCount === 1 ? "" : "s"} — see the findings link above.
            </p>
          ) : (
            // `getScan` hasn't resolved yet, or it failed -- absence is not the
            // same claim as zero, so this never falls back to "No findings".
            <p data-testid="findings-summary" role="status" aria-live="polite">
              findings count unknown — see the findings link above to check.
            </p>
          )}
        </TerminalFrame>
      )}
```

- [ ] **Step 4: Run the tests**

Run: `npx tsc --noEmit && npx playwright test tests/live-scan.spec.ts tests/a11y.spec.ts -g "live scan|terminal|progress|findings count"`
Expected: PASS. In particular `progress is announced to assistive technology` and `a non-zero findings count is never reported as no findings` must still pass — they prove the single-status invariant survived.

- [ ] **Step 5: Commit**

```bash
git add "web/app/scans/[id]/page.tsx" web/tests/live-scan.spec.ts
git commit -m "feat(web): fade in the live-scan terminal summary

Incoming frame only (200ms easeOut) -- the progress announcer unmounts in
the same render, so the one-role=status-at-a-time invariant holds."
```

---

### Task 3: Scan-setup polish (spacing, mode lock, dropzone, submit button)

**Files:**
- Modify: `web/app/components/ScopeFileField.tsx:31-92`
- Modify: `web/app/components/ModeSelector.tsx:28-58`
- Modify: `web/app/page.tsx:63-99`
- Modify: `web/app/globals.css:514-568` (scan-setup block) — edits + additions
- Test: `web/tests/scan-setup.spec.ts`

**Interfaces:**
- Consumes: nothing from `motion` — this screen is pure CSS transitions (spec D4: "plain CSS for simple hover/focus states"), covered by the global reduced-motion rule.
- Produces: attributes tests and CSS key on — `[data-dragging]` on `.bok-scope-file-field`, `[data-unlocked]` on `.bok-mode-selector`, `.bok-submit[data-submitting]` with an inner `.bok-submit-label`.

- [ ] **Step 1: Write the failing tests**

Before writing the in-flight test, confirm the request path `createScan` posts to: `grep -n "fetch(" web/src/lib/api.ts` — adjust the `page.route` glob below if it is not `**/api/scans`.

Append to `web/tests/scan-setup.spec.ts`:

```ts
// Web UI redesign (spec §4.1). Each test asserts an end state -- an
// attribute or a computed style -- not a transition's intermediate frames.
test("the dropzone marks itself while a file is dragged over it", async ({ page }) => {
  await page.goto("/");
  const zone = page.locator(".bok-scope-file-field");
  await expect(zone).toHaveAttribute("data-dragging", "false");
  await zone.dispatchEvent("dragenter");
  await expect(zone).toHaveAttribute("data-dragging", "true");
  await zone.dispatchEvent("dragleave");
  await expect(zone).toHaveAttribute("data-dragging", "false");
});

test("the mode selector records the lock state for its transition", async ({ page }) => {
  await page.goto("/");
  const selector = page.locator(".bok-mode-selector");
  await expect(selector).toHaveAttribute("data-unlocked", "false");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-valid.json");
  await expect(selector).toHaveAttribute("data-unlocked", "true");
});

test("the submit button reads disabled until a target is typed", async ({ page }) => {
  await page.goto("/");
  const submit = page.getByRole("button", { name: /start scan/i });
  await expect(submit).toBeDisabled();
  await expect(submit).toHaveCSS("cursor", "not-allowed");
  await page.getByLabel(/target/i).fill("https://example.test/mcp");
  await expect(submit).toBeEnabled();
  await expect(submit).toHaveCSS("cursor", "pointer");
});

test("the submit button shows its submitting state while the request is in flight", async ({ page }) => {
  // Hold the API response open so the in-flight state is observable.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  await page.route("**/api/scans", async (route) => {
    await held;
    await route.fulfill({ status: 202, contentType: "application/json", body: JSON.stringify({ id: "9" }) });
  });
  await page.goto("/");
  await page.getByLabel(/target/i).fill("https://example.test/mcp");
  const submit = page.getByRole("button", { name: /start/i });
  await submit.click();
  await expect(submit).toHaveAttribute("data-submitting", "true");
  release();
  await page.waitForURL(/\/scans\/9/);
});

test("reduced motion leaves every scan-setup end state intact", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-valid.json");
  expect(await page.locator(".bok-mode-selector").getAttribute("data-unlocked")).toBe("true");
  await expect(page.getByRole("radio", { name: /active/i })).toBeEnabled();
  await page.getByLabel(/target/i).fill("x");
  await expect(page.getByRole("button", { name: /start scan/i })).toHaveCSS("cursor", "pointer");
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx playwright test tests/scan-setup.spec.ts`
Expected: the five new tests FAIL (attributes missing; cursor is `default`). The existing five pass.

- [ ] **Step 3: Add the state attributes in the components**

`web/app/components/ScopeFileField.tsx` — in the component body add a second state next to `fileName`:

```tsx
  const [dragging, setDragging] = useState(false);
```

and replace the outer `<div className="bok-scope-file-field" …>` opening tag with:

```tsx
    <div
      className="bok-scope-file-field"
      data-dragging={dragging}
      onDragEnter={() => setDragging(true)}
      onDragOver={(e) => {
        e.preventDefault();
        if (!dragging) setDragging(true);
      }}
      onDragLeave={(e) => {
        // Leaving a child still fires dragleave on the parent; only clear
        // when the pointer has actually left this element.
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={(e) => {
        setDragging(false);
        handleDrop(e);
      }}
    >
```

`web/app/components/ModeSelector.tsx` — change the opening tag to:

```tsx
    <fieldset className="bok-mode-selector" data-unlocked={activeUnlocked}>
```

`web/app/page.tsx` — replace the submit button with:

```tsx
        <button
          type="submit"
          className="bok-submit"
          data-submitting={submitting}
          disabled={submitting || target.trim() === ""}
        >
          <span className="bok-submit-label">{submitting ? "Starting scan…" : "Start scan"}</span>
        </button>
```

(React renders `data-dragging={false}` as `data-dragging="false"`, which is what the tests assert.)

- [ ] **Step 4: Write the CSS**

In `web/app/globals.css`, inside the `/* Scan setup screen (task 11). */` block:

Replace the existing `.bok-scan-setup form` rule with:

```css
.bok-scan-setup {
  max-width: 32rem;
}
.bok-scan-setup h1 {
  margin-bottom: var(--density-cell-y);
}
.bok-scan-setup > p {
  margin: 0 0 calc(var(--density-gap) * 3);
  color: var(--neutral-600);
}
.bok-scan-setup form {
  display: flex;
  flex-direction: column;
  gap: calc(var(--density-gap) * 2);
}
```

Replace the existing `.bok-field input[type="text"]` rule with:

```css
.bok-field input[type="text"] {
  border: 1px solid var(--neutral-300);
  border-radius: var(--radius-control);
  padding: var(--density-cell-y) var(--density-cell-x);
  background: var(--paper);
  color: var(--ink);
  transition: border-color 150ms ease-out, box-shadow 150ms ease-out;
}
.bok-field input[type="text"]:hover {
  border-color: var(--neutral-400);
}
.bok-field input[type="text"]:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
  border-color: var(--accent);
}
```

Replace the existing `.bok-mode-option` and `.bok-lock-reason` rules with:

```css
.bok-mode-option {
  display: flex;
  align-items: center;
  gap: 0.5em;
  padding: var(--density-cell-y) var(--density-cell-x);
  border: 1px solid transparent;
  border-radius: var(--radius-cell);
  transition: background-color 200ms ease-out, border-color 200ms ease-out, color 200ms ease-out;
}
.bok-mode-option:has(input:not(:disabled)) {
  cursor: pointer;
}
.bok-mode-option:has(input:not(:disabled)):hover {
  background: var(--neutral-50);
  border-color: var(--neutral-200);
}
.bok-mode-option:has(input:disabled) {
  color: var(--neutral-500);
  cursor: not-allowed;
}
.bok-mode-option:has(input:focus-visible) {
  border-color: var(--accent);
}
.bok-mode-selector[data-unlocked="true"] .bok-mode-option:has(input[value="active"]) {
  border-color: var(--neutral-200);
}
.bok-lock-reason {
  color: var(--severity-medium);
  border-left: 2px solid var(--severity-medium);
  padding-left: var(--density-cell-x);
  font-size: 0.9em;
  transition: border-left-color 150ms ease-out, color 150ms ease-out;
}
/* Informational, not interactive (no tab stop): hover only deepens the
   rule so a pointer user can tell it's the thing explaining the lock. */
.bok-lock-reason:hover {
  border-left-color: var(--ink);
}
```

Replace the existing `.bok-scope-file-field` rule with:

```css
.bok-scope-file-field {
  display: flex;
  flex-direction: column;
  gap: var(--density-cell-y);
  border: 1px dashed var(--neutral-300);
  border-radius: var(--radius-control);
  padding: var(--density-gap);
  transition: border-color 150ms ease-out, background-color 150ms ease-out;
}
.bok-scope-file-field:hover,
.bok-scope-file-field:focus-within {
  border-color: var(--neutral-500);
}
.bok-scope-file-field[data-dragging="true"] {
  border-color: var(--accent);
  border-style: solid;
  background: color-mix(in oklch, var(--accent) 6%, transparent);
}
```

Append after `.bok-scope-file-name`:

```css
/* Submit: disabled→enabled is a colour/cursor transition (150ms); the
   in-flight state pulses the label -- never a spinner (00 §5.5). */
.bok-submit {
  align-self: flex-start;
  padding: var(--density-cell-y) calc(var(--density-cell-x) * 2);
  border: 1px solid var(--ink);
  border-radius: var(--radius-control);
  background: var(--ink);
  color: var(--paper);
  font: inherit;
  cursor: pointer;
  transition: background-color 150ms ease-out, border-color 150ms ease-out, color 150ms ease-out;
}
.bok-submit:hover:not(:disabled) {
  background: var(--neutral-800);
  border-color: var(--neutral-800);
}
.bok-submit:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
.bok-submit:disabled {
  background: var(--neutral-100);
  border-color: var(--neutral-200);
  color: var(--neutral-500);
  cursor: not-allowed;
}
.bok-submit[data-submitting="true"] .bok-submit-label {
  display: inline-block;
  animation: bok-submit-pulse 1.2s ease-in-out infinite;
}
@keyframes bok-submit-pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.55;
  }
}
```

Contrast note: `--neutral-500` on `--neutral-100` is the disabled button — disabled controls are exempt from WCAG 1.4.3 and axe does not flag them. `--paper` on `--ink` is the enabled button: the page's own text/ground pair inverted, ≥ 12:1.

- [ ] **Step 5: Run the tests**

Run: `npx tsc --noEmit && npm run lint && npx playwright test tests/scan-setup.spec.ts tests/a11y.spec.ts -g "scan setup|dropzone|mode selector|submit"`
Expected: all PASS. If `is fully operable from the keyboard` or `has a visible focus ring` fails, the first Tab must still land on `#target` with a visible outline — the new `:focus-visible` rule sets one explicitly, so a failure means a selector typo.

- [ ] **Step 6: Commit**

```bash
git add web/app/components/ScopeFileField.tsx web/app/components/ModeSelector.tsx web/app/page.tsx web/app/globals.css web/tests/scan-setup.spec.ts
git commit -m "feat(web): scan-setup hover/focus/drag states and submit transitions

Pure CSS (global reduced-motion rule covers it). Dropzone marks
data-dragging, mode selector marks data-unlocked, submit pulses its label
while in flight -- never a spinner."
```

---

### Task 4: Findings table row reveal, expand fade, severity-badge hover

**Files:**
- Modify: `web/src/lib/_bok-ui.tsx:21-31` (imports), `:394-400` (state), `:541-622` (row render)
- Modify: `web/app/globals.css:303-313` (`.bok-severity-badge`), `:372-377` (`.bok-row-expandable`)
- Test: `web/tests/findings.spec.ts`

**Interfaces:**
- Consumes: `useRiseIn`, `useFadeIn` from `web/src/lib/motion.ts`.
- Produces: `[data-testid="finding-row"]` carries `data-entered`; `[data-testid="finding-row-expanded"]` contains a `div.bok-finding-expanded-reveal` carrying `data-entered`.

Design constraints from spec §4.3 (already argued there, do not re-litigate):
- Reveal runs on **first** mount of a row id only. The virtualizer remounts rows that scroll back into view; a `Set<string>` of revealed ids in a `useRef` makes the remount render its end state (`skip: true`).
- Expand is **opacity-only**. No height animation — `<tr>` doesn't transition height and the fixed `estimateSize` would not track it.
- There is no filter on this screen today; "on filter change" from the spec has nothing to attach to. Rows are keyed by `row.id`, so a future filter that removes/adds rows will get the mount reveal for genuinely new rows for free.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/findings.spec.ts`:

```ts
// Web UI redesign (spec §4.3): rows rise in on first mount; the expanded
// reproduction fades in. End-state assertions only.
test("finding rows reach their entered state", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const rows = page.getByTestId("finding-row");
  await expect(rows.first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(rows.last()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
});

test("an expanded row's content reaches its entered state", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("finding-row").first().click();
  const reveal = page.getByTestId("finding-row-expanded").locator(".bok-finding-expanded-reveal");
  await expect(reveal).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(page.getByTestId("reproduction")).toBeVisible();
});

test("a severity badge lifts on hover, keeping glyph and label", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const badge = page.getByTestId("severity-badge").first();
  const before = await badge.getAttribute("data-glyph");
  await badge.hover();
  await expect(badge).toHaveCSS("transform", "matrix(1, 0, 0, 1, 0, -1)");
  expect(await badge.getAttribute("data-glyph")).toBe(before);
  await expect(badge).not.toHaveText("");
});

test("reduced motion renders rows and expansions already entered", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1/findings?fixture=mixed");
  const first = page.getByTestId("finding-row").first();
  await expect(first).toBeVisible();
  expect(await first.getAttribute("data-entered")).toBe("true");
  await first.click();
  const reveal = page.getByTestId("finding-row-expanded").locator(".bok-finding-expanded-reveal");
  await expect(reveal).toBeVisible();
  expect(await reveal.getAttribute("data-entered")).toBe("true");
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx playwright test tests/findings.spec.ts`
Expected: the four new tests FAIL (no `data-entered`; no `.bok-finding-expanded-reveal`; transform is `none`). The eight existing tests pass.

- [ ] **Step 3: Add the reveal wrappers to `FindingsTable`**

In `web/src/lib/_bok-ui.tsx`, extend the imports (after the `diff` import):

```tsx
import { motion } from "motion/react";

import { useFadeIn, useRiseIn } from "./motion";
```

(`./motion` — this file lives in `web/src/lib/`, the same directory as `motion.ts`.) Add `type ComponentPropsWithoutRef` to the `react` import list. If tsc rejects `ComponentPropsWithoutRef<typeof motion.tr>`, use `HTMLMotionProps<"tr">` from `"motion/react"` in its place — same shape, motion's own name for it.

Add two internal components immediately above `export function FindingsTable(`:

```tsx
/**
 * A finding row that rises in on its *first* mount only (spec §4.3). The
 * virtualizer remounts rows that scroll back into view; `skip` is true for
 * an id that has already been revealed, so a remount renders the end state
 * instead of shimmering on every scroll. `onRevealed` fires both when the
 * animation completes and when the row was rendered already-entered
 * (reduced motion / skip), so the set is complete either way.
 */
function RevealRow({
  index,
  skip,
  onRevealed,
  ...rest
}: {
  index: number;
  skip: boolean;
  onRevealed: () => void;
} & Omit<ComponentPropsWithoutRef<typeof motion.tr>, "initial" | "animate" | "transition" | "onAnimationComplete">) {
  const entrance = useRiseIn({ index, skip, duration: 0.25 });
  const entered = entrance["data-entered"] === "true";
  useEffect(() => {
    // Idempotent (adds to a Set), so re-running on an inline-arrow
    // `onRevealed` identity change is harmless.
    if (entered) onRevealed();
  }, [entered, onRevealed]);
  return (
    <motion.tr
      {...rest}
      {...entrance}
      onAnimationComplete={() => {
        entrance.onAnimationComplete();
        onRevealed();
      }}
    />
  );
}

/** The expanded row's content, opacity-only (spec §4.3 -- never height). */
function RevealExpanded({ children }: { children: ReactNode }) {
  const fade = useFadeIn();
  return (
    <motion.div {...fade} className="bok-finding-expanded-reveal">
      {children}
    </motion.div>
  );
}
```

Inside `FindingsTable`, next to the other refs:

```tsx
  // Ids that have completed their reveal once -- see RevealRow.
  const revealedIds = useRef<Set<string>>(new Set());
```

Replace the row's opening `<tr data-testid="finding-row" … onClick={onRowClick(row.id)}>` with:

```tsx
                  <RevealRow
                    index={virtualRow.index - (virtualRows[0]?.index ?? 0)}
                    skip={revealedIds.current.has(row.id)}
                    onRevealed={() => revealedIds.current.add(row.id)}
                    data-testid="finding-row"
                    style={{ height: rowHeight }}
                    className={cx(renderExpanded && "bok-row-expandable")}
                    onClick={onRowClick(row.id)}
                  >
```

and its matching closing `</tr>` (the one immediately before `{renderExpanded && expanded && (`) with `</RevealRow>`. The `index` is relative to the first *visible* row so the stagger starts at 0 for whatever is on screen.

Replace the expanded row:

```tsx
                  {renderExpanded && expanded && (
                    <tr data-testid="finding-row-expanded">
                      <td colSpan={FINDINGS_COLUMNS.length}>
                        <RevealExpanded>{renderExpanded(row)}</RevealExpanded>
                      </td>
                    </tr>
                  )}
```

- [ ] **Step 4: CSS for the badge hover and row hover**

In `web/app/globals.css`, replace the `.bok-severity-badge` rule with:

```css
.bok-severity-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.35em;
  font-family: var(--font-ibm-plex-mono), ui-monospace, monospace;
  font-size: 0.85em;
  padding: 2px 6px;
  border-radius: var(--radius-cell);
  border: 1px solid currentColor;
  transition: transform 150ms ease-out, filter 150ms ease-out;
}
/* Decorative only -- glyph + label + colour encoding is unchanged. */
.bok-severity-badge:hover {
  transform: translateY(-1px);
  filter: brightness(1.05);
}
```

Replace the `.bok-row-expandable` pair with:

```css
.bok-row-expandable {
  cursor: pointer;
  transition: background-color 150ms ease-out;
}
.bok-row-expandable:hover {
  background: var(--neutral-50);
}
```

(No change to `.bok-finding-expanded` — the motion wrapper carries the opacity.)

Spec §4.3 also asks for spacing/weight polish on the `ConformanceStrip` header, no motion. Replace the `.bok-conformance-strip` rule (`globals.css:649-656`) with:

```css
.bok-conformance-strip {
  font-family: var(--font-ibm-plex-mono), ui-monospace, monospace;
  font-size: 0.9em;
  font-weight: 600;
  letter-spacing: 0.01em;
  padding: var(--density-cell-y) var(--density-cell-x);
  margin-bottom: calc(var(--density-gap) * 2);
  border: 1px solid var(--accent);
  border-radius: var(--radius-cell);
  background: color-mix(in oklch, var(--accent) 8%, transparent);
}
```

(IBM Plex Mono 600 is already loaded in `layout.tsx`; `findings.spec.ts`'s three conformance-strip tests are text assertions and are unaffected.)

- [ ] **Step 5: Run the tests**

Run: `npx tsc --noEmit && npm run lint && npx playwright test tests/findings.spec.ts tests/tokens.spec.ts tests/provenance-rail.spec.ts tests/a11y.spec.ts -g "findings|severity|numbers|rail|claim|row"`
Expected: PASS, including `Enter on a claim inside an expandable row only opens the rail` (the `onClick`/`onKeyDown` wiring on the row is unchanged; only the element type is `motion.tr`).

The hover assertion is not run under reduced motion — the global rule zeroes the *duration*, not the end value, so a hover still lands at `-1px`; that is the intended reduced-motion behaviour for a hover state.

- [ ] **Step 6: Commit**

```bash
git add web/src/lib/_bok-ui.tsx web/app/globals.css web/tests/findings.spec.ts
git commit -m "feat(web): findings rows rise in once, expansions fade, badges lift on hover

Reveal is tracked per row id so virtualizer remounts render the end state;
expand is opacity-only because <tr> cannot transition height and the
virtualizer's fixed estimateSize would not track it."
```

---

### Task 5: Capability graph — node entrance, edge fade, hover-connected edges

**Files:**
- Modify: `web/app/components/CapabilityGraph.tsx:17-21` (imports), `:74-97` (state), `:102-158` (svg body), `:210-301` (ToolNode / FlaggedToolNode)
- Modify: `web/app/globals.css:692-741` (graph node/edge rules)
- Test: `web/tests/graph.spec.ts`

**Interfaces:**
- Consumes: `useScaleIn`, `useFadeIn` from `web/src/lib/motion.ts`.
- Produces: `[data-testid="node"|"node-flagged"]` carry `data-entered`; `[data-testid="edge"]` carry `data-entered` and `data-tool`, and while a tool node is hovered/focused, `data-connected="true"` on its edges and `data-dimmed="true"` on every other edge.

Binding constraints (spec §4.4, §5):
- **Never touch `strokeDasharray`.** Edge entrance is opacity; dimming is `stroke-opacity` (a separate CSS property, so it does not fight the inline `opacity` motion sets).
- The `transform="translate(x,y)"` **attribute** positions each node. `motion` writes `style.transform`, and a CSS transform *overrides* the presentation attribute — so scale/opacity go on an **inner** `<motion.g>` with `transform-box: fill-box; transform-origin: center`, leaving the outer positioning `<g>` untouched.
- Flagged nodes: entrance → pulse, sequenced. `FlaggedToolNode` stays `"pending"` until the inner entrance's `onAnimationComplete`, then flips to `"playing"`; reduced motion still goes straight to `"skipped"` in the existing `useLayoutEffect`.
- Keyboard: node `onFocus`/`onBlur` set the same highlight state as pointer, so the edge highlighting is keyboard-reachable too. `ProvenanceRail` on activation is unchanged.

- [ ] **Step 1: Write the failing tests**

First check the `mixed-derivation` fixture has at least two distinct tools: `grep -rn "mixed-derivation" web/app` and read the fixture. If every edge belongs to one tool, the `others` branch below is guarded by an `if` and the test still proves the connected path.

Append to `web/tests/graph.spec.ts`:

```ts
// Web UI redesign (spec §4.4). End-state assertions; dasharray is checked
// again because it is the derivation encoding and must survive untouched.
test("nodes and edges reach their entered state", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  await expect(page.getByTestId("node").first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  const edges = page.getByTestId("edge");
  await expect(edges.first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(edges.last()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
});

test("the entrance never changes an edge's dash pattern", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const probe = page.locator("[data-derivation='probe']").first();
  const initial = await probe.getAttribute("stroke-dasharray");
  await expect(probe).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  expect(await probe.getAttribute("stroke-dasharray")).toBe(initial);
  expect(await probe.evaluate((el) => getComputedStyle(el).strokeDasharray)).not.toBe("none");
});

test("a flagged node pulses only after it has entered", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "pending");
  await expect(node).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(node).toHaveAttribute("data-pulse", /playing|done/);
  await expect(node).toHaveAttribute("data-pulse", "done", { timeout: 3_000 });
});

test("hovering a tool node marks its edges connected and dims the rest", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const nodes = page.getByTestId("node");
  await expect(nodes.first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  const label = await nodes.first().getAttribute("aria-label");
  const toolName = label!.replace(/^Tool /, "").replace(/, policy-flagged$/, "");
  await nodes.first().hover();
  const connected = page.locator(`[data-testid="edge"][data-tool="${toolName}"]`);
  await expect(connected.first()).toHaveAttribute("data-connected", "true");
  const others = page.locator(`[data-testid="edge"]:not([data-tool="${toolName}"])`);
  if (await others.count()) await expect(others.first()).toHaveAttribute("data-dimmed", "true");
  await page.mouse.move(0, 0);
  await expect(connected.first()).toHaveAttribute("data-connected", "false");
});

test("focusing a tool node highlights its edges from the keyboard too", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  await page.keyboard.press("Tab");
  const node = page.getByTestId("node").first();
  await expect(node).toBeFocused();
  const toolName = (await node.getAttribute("aria-label"))!.replace(/^Tool /, "");
  await expect(page.locator(`[data-testid="edge"][data-tool="${toolName}"]`).first()).toHaveAttribute("data-connected", "true");
});

test("reduced motion renders nodes and edges already entered and still pulses nothing", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node").first();
  await expect(node).toBeVisible();
  expect(await node.getAttribute("data-entered")).toBe("true");
  const edge = page.getByTestId("edge").first();
  expect(await edge.getAttribute("data-entered")).toBe("true");
  await expect(page.getByTestId("node-flagged").first()).toHaveAttribute("data-pulse", "skipped");
});
```

Note on the `focusing` test: the first Tab lands on the first tool node (existing test `the graph is fully navigable from the keyboard` proves this); in the `mixed-derivation` fixture that node may be flagged (`data-testid="node-flagged"`, not `node`). If `toBeFocused` fails for that reason, change the locator to `page.locator('[data-testid="node"], [data-testid="node-flagged"]').first()` and strip `, policy-flagged` as the hover test does.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx playwright test tests/graph.spec.ts`
Expected: six new tests FAIL (no `data-entered`, `data-tool`, `data-connected`; flagged node goes straight to `playing`). Seven existing tests pass.

- [ ] **Step 3: Implement**

`web/app/components/CapabilityGraph.tsx` — imports become:

```tsx
import { motion } from "motion/react";
import { useLayoutEffect, useMemo, useState, type KeyboardEvent } from "react";

import { DERIVATION_META, type Derivation } from "@/src/lib/_bok-ui";
import type { Capability, CapabilityEdge } from "@/src/lib/api";
import { useFadeIn, useScaleIn } from "@/src/lib/motion";
import { EdgeTooltip } from "./EdgeTooltip";
```

In `CapabilityGraph`, add state beside `activeEdge`:

```tsx
  // Pointer-hovered or keyboard-focused tool; its edges are marked
  // connected, every other edge dimmed (spec §4.4). Keyboard sets it too,
  // so the highlight is not a pointer-only affordance.
  const [highlightedTool, setHighlightedTool] = useState<string | null>(null);
```

Change the `ToolNode` render to pass `index` and the highlight callback:

```tsx
        {toolOrder.map((tool, index) => (
          <ToolNode
            key={tool}
            tool={tool}
            index={index}
            x={TOOL_X}
            y={toolY.get(tool) ?? TOP_PAD}
            flagged={flaggedTools.has(tool)}
            onActivate={() => onActivateTool(tool)}
            onHighlight={setHighlightedTool}
          />
        ))}
```

Replace the `edges.map` inside the `<svg>` with a component render (hooks cannot be called inside `map`):

```tsx
        {edges.map((edge, i) => (
          <Edge
            key={`${edge.tool}-${edge.capability}-${i}`}
            edge={edge}
            index={i}
            y1={toolY.get(edge.tool) ?? TOP_PAD}
            y2={capY.get(edge.capability) ?? TOP_PAD}
            highlightedTool={highlightedTool}
            onActive={setActiveEdge}
          />
        ))}
```

Add the `Edge` component after `CapabilityGraph`:

```tsx
interface EdgeProps {
  edge: CapabilityEdge;
  index: number;
  y1: number;
  y2: number;
  highlightedTool: string | null;
  onActive: (update: (current: CapabilityEdge | null) => CapabilityEdge | null) => void;
}

/**
 * One edge. Entrance is an opacity fade (spec §4.4): `strokeDasharray` is
 * the derivation encoding and is never animated. Dimming uses
 * `stroke-opacity` in CSS so it doesn't fight the inline `opacity` motion
 * owns. `onActive` takes a functional update so leaving/blurring one edge
 * never clears a different edge that became active in between.
 */
function Edge({ edge, index, y1, y2, highlightedTool, onActive }: EdgeProps) {
  const fade = useFadeIn({ index, duration: 0.4 });
  const connected = highlightedTool === edge.tool;
  const dimmed = highlightedTool !== null && !connected;
  const clearIfCurrent = () => onActive((current) => (current === edge ? null : current));
  return (
    <motion.line
      {...fade}
      data-testid="edge"
      data-derivation={edge.derivation}
      data-tool={edge.tool}
      data-connected={connected}
      data-dimmed={dimmed}
      className="bok-graph-edge"
      x1={TOOL_X}
      y1={y1}
      x2={CAP_X}
      y2={y2}
      strokeDasharray={DASH_ARRAY[edge.derivation]}
      tabIndex={0}
      aria-label={`${edge.tool} has ${CAPABILITY_LABEL[edge.capability]}, ${DERIVATION_META[edge.derivation].label}-derived: ${edge.rationale}`}
      onMouseEnter={() => onActive(() => edge)}
      onMouseLeave={clearIfCurrent}
      onFocus={() => onActive(() => edge)}
      onBlur={clearIfCurrent}
    >
      <title>{`${DERIVATION_META[edge.derivation].label}: ${edge.rationale}`}</title>
    </motion.line>
  );
}
```

`setActiveEdge` from `useState` already accepts a functional updater, so `onActive={setActiveEdge}` type-checks against this signature.

Update `ToolNodeProps` and `ToolNode`:

```tsx
interface ToolNodeProps {
  tool: string;
  index: number;
  x: number;
  y: number;
  flagged: boolean;
  onActivate: () => void;
  onHighlight: (tool: string | null) => void;
}

function ToolNode({ tool, index, x, y, flagged, onActivate, onHighlight }: ToolNodeProps) {
  // Unconditional hook call (rules of hooks); unused on the flagged path,
  // where FlaggedToolNode owns its own entrance.
  const entrance = useScaleIn({ index });
  if (flagged) {
    return <FlaggedToolNode tool={tool} index={index} x={x} y={y} onActivate={onActivate} onHighlight={onHighlight} />;
  }
  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool"
      data-testid="node"
      data-entered={entrance["data-entered"]}
      role="button"
      tabIndex={0}
      aria-label={`Tool ${tool}`}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (!activates(event)) return;
        event.preventDefault();
        onActivate();
      }}
      onMouseEnter={() => onHighlight(tool)}
      onMouseLeave={() => onHighlight(null)}
      onFocus={() => onHighlight(tool)}
      onBlur={() => onHighlight(null)}
    >
      {/* Inner group carries the entrance: motion writes style.transform,
          which would override the positioning `transform` attribute above. */}
      <motion.g {...entrance} className="bok-graph-node-inner">
        <circle r={16} />
        <text x={-24} dy="0.35em" textAnchor="end">
          {tool}
        </text>
      </motion.g>
    </g>
  );
}
```

Replace `FlaggedToolNode`:

```tsx
function FlaggedToolNode({ tool, index, x, y, onActivate, onHighlight }: Omit<ToolNodeProps, "flagged">) {
  const [pulse, setPulse] = useState<PulseState>("pending");
  const entrance = useScaleIn({ index });

  // useLayoutEffect (not useEffect): resolves before the browser paints, so
  // a reduced-motion viewer never sees `data-pulse` pass through "playing"
  // at all -- it goes straight from the unpainted "pending" first render to
  // "skipped". A motion-allowed viewer stays "pending" here; the entrance's
  // onAnimationComplete below is what starts the pulse (spec §4.4:
  // entrance → pulse, sequenced, never stacked).
  useLayoutEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) setPulse("skipped");
  }, []);

  const ring = pulse === "done" || pulse === "skipped";

  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool bok-graph-node-flagged"
      data-testid="node-flagged"
      data-entered={entrance["data-entered"]}
      data-pulse={pulse}
      data-ring={ring}
      role="button"
      tabIndex={0}
      aria-label={`Tool ${tool}, policy-flagged`}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (!activates(event)) return;
        event.preventDefault();
        onActivate();
      }}
      onMouseEnter={() => onHighlight(tool)}
      onMouseLeave={() => onHighlight(null)}
      onFocus={() => onHighlight(tool)}
      onBlur={() => onHighlight(null)}
    >
      <motion.g
        {...entrance}
        className="bok-graph-node-inner"
        onAnimationComplete={() => {
          entrance.onAnimationComplete();
          setPulse((current) => (current === "pending" ? "playing" : current));
        }}
      >
        {pulse === "playing" && (
          <circle r={16} className="bok-graph-pulse-ring" onAnimationEnd={() => setPulse("done")} />
        )}
        {ring && <circle r={22} className="bok-graph-static-ring" />}
        <circle r={16} className="bok-graph-node-circle" />
        <text x={-24} dy="0.35em" textAnchor="end">
          {tool}
        </text>
      </motion.g>
    </g>
  );
}
```

- [ ] **Step 4: CSS**

In `web/app/globals.css`, after `.bok-graph-node-tool:focus-visible circle { … }` add:

```css
/* Entrance scale must pivot on the node itself, not the SVG origin. */
.bok-graph-node-inner {
  transform-box: fill-box;
  transform-origin: center;
}
```

Replace the `.bok-graph-edge` rule (keep the `:hover`/`:focus-visible` rules that follow it) with:

```css
.bok-graph-edge {
  stroke: var(--neutral-400);
  stroke-width: 1.5;
  transition: stroke 150ms ease-out, stroke-width 150ms ease-out, stroke-opacity 150ms ease-out;
}
/* Hover/focus on a tool node: its edges read as connected, the rest recede.
   stroke-opacity, not opacity -- motion owns inline opacity for the
   entrance. Dasharray (the derivation encoding) is never touched. */
.bok-graph-edge[data-connected="true"] {
  stroke: var(--ink);
  stroke-width: 2;
}
.bok-graph-edge[data-dimmed="true"] {
  stroke-opacity: 0.3;
}
```

- [ ] **Step 5: Run the tests**

Run: `npx tsc --noEmit && npm run lint && npx playwright test tests/graph.spec.ts tests/a11y.spec.ts -g "graph|node|edge"`
Expected: PASS — all 13 graph tests (7 existing + 6 new) and the four `capability graph` a11y tests. The pre-existing `a policy-flagged node pulses once and then holds a ring` still passes because `toHaveAttribute("data-pulse", "playing")` retries until the entrance completes (~300ms + stagger).

If tsc rejects `motion.line`/`motion.g` props (`x1`, `strokeDasharray`), check the import is `motion` from `"motion/react"` (not `"motion"`); motion 13 types SVG elements from React's `SVGProps`.

- [ ] **Step 6: Commit**

```bash
git add web/app/components/CapabilityGraph.tsx web/app/globals.css web/tests/graph.spec.ts
git commit -m "feat(web): capability graph entrance and hover-connected edges

Nodes scale in on an inner motion.g (the positioning transform attribute
stays untouched); flagged nodes pulse only after entering. Edges fade in
-- stroke-dasharray is the derivation encoding and is never animated.
Hover/focus on a tool marks its edges connected and dims the rest via
stroke-opacity, keyboard-reachable."
```

---

### Task 6: Drift diff highlight-in, timeline hover, print safety

**Files:**
- Modify: `web/app/globals.css:445-500` (RunTimeline + DiffView blocks)
- Modify: `web/app/print.css:9-31`
- Test: `web/tests/drift.spec.ts`; `web/tests/print.spec.ts` (unchanged, must stay green)

**Interfaces:**
- Consumes: nothing from `motion` — CSS keyframes (the diff is static once rendered; there is no enter/exit to orchestrate).
- Produces: nothing consumed later.

The drift screen renders `DiffView granularity="word"` (`drift/page.tsx:127`): the highlighted elements are the `.bok-diff-word-added` / `.bok-diff-word-removed` spans, not lines. The line-mode `.bok-diff-add` / `.bok-diff-remove` get the same keyframe so a future line-mode caller matches. The `+`/`−` prefix and `data-glyph` are the non-colour encoding and are untouched.

- [ ] **Step 1: Write the failing tests**

Append to `web/tests/drift.spec.ts`:

```ts
// Web UI redesign (spec §4.5): added/removed spans highlight in via a
// background keyframe; the glyph encoding is unaffected.
test("added and removed spans settle on a highlighted background", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const added = page.getByTestId("added").first();
  await expect(added).toHaveCSS("animation-name", "bok-diff-in");
  await expect
    .poll(async () => added.evaluate((el) => getComputedStyle(el).backgroundColor), { timeout: 3_000 })
    .not.toBe("rgba(0, 0, 0, 0)");
  await expect(added).toHaveAttribute("data-glyph", "+");
});

test("a timeline item responds to hover", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const item = page.locator(".bok-timeline-item").first();
  const before = await item.evaluate((el) => getComputedStyle(el).borderLeftColor);
  await item.hover();
  await expect.poll(async () => item.evaluate((el) => getComputedStyle(el).borderLeftColor)).not.toBe(before);
});

test("reduced motion renders the diff highlight immediately", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/2/drift?fixture=changed-description");
  const added = page.getByTestId("added").first();
  await expect(added).toBeVisible();
  expect(await added.evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe("rgba(0, 0, 0, 0)");
  expect(await added.evaluate((el) => getComputedStyle(el).animationDuration)).toBe("0.001ms");
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx playwright test tests/drift.spec.ts`
Expected: `animation-name` is `none` → first and third FAIL; timeline hover FAILS (colour unchanged). Existing tests pass.

- [ ] **Step 3: CSS**

In `web/app/globals.css`, replace the `.bok-timeline-item` rule with:

```css
.bok-timeline-item {
  display: flex;
  gap: var(--density-gap);
  border-left: 2px solid var(--neutral-200);
  padding-left: var(--density-cell-x);
  transition: border-left-color 150ms ease-out, background-color 150ms ease-out;
}
.bok-timeline-item:hover {
  border-left-color: var(--accent);
  background: color-mix(in oklch, var(--accent) 5%, transparent);
}
```

The `.bok-timeline-error` / `.bok-timeline-ok` rules that follow have equal specificity and come later, so a status colour wins over the hover accent on those items. If the first fixture item is an `ok`/`error` item, the hover test's `borderLeftColor` would not change — in that case scope the test to `.bok-timeline-item:not(.bok-timeline-ok):not(.bok-timeline-error)` and, if no such item exists in the fixture, assert `backgroundColor` changed instead (the background rule has no status override).

Replace the four diff colour rules so each carries the keyframe:

```css
.bok-diff-add {
  background: color-mix(in oklch, var(--provenance-verified) 18%, transparent);
  animation: bok-diff-in 300ms ease-out backwards;
}
.bok-diff-remove {
  background: color-mix(in oklch, var(--severity-critical) 18%, transparent);
  animation: bok-diff-in 300ms ease-out backwards;
}
```

and

```css
.bok-diff-word-removed {
  color: var(--severity-critical);
  text-decoration: line-through;
  background: color-mix(in oklch, var(--severity-critical) 12%, transparent);
  animation: bok-diff-in 300ms ease-out backwards;
}
.bok-diff-word-added {
  color: var(--provenance-verified);
  background: color-mix(in oklch, var(--provenance-verified) 12%, transparent);
  animation: bok-diff-in 300ms ease-out backwards;
}
/* From transparent to whatever background the rule above declares -- the
   `to` frame is implicit, so one keyframe serves all four rules. The +/−
   prefix and data-glyph are the colour-independent encoding; untouched. */
@keyframes bok-diff-in {
  from {
    background-color: transparent;
  }
}
```

- [ ] **Step 4: Print safety**

In `web/app/print.css`, inside the `@media print` block, after the `:focus` rule add:

```css
  /* Nothing animates on paper. Belt-and-braces over the reduced-motion
     rule: a print snapshot taken mid-keyframe would otherwise capture a
     half-highlighted diff or a half-risen row. */
  *,
  *::before,
  *::after {
    animation: none !important;
    transition: none !important;
    opacity: 1 !important;
    transform: none !important;
  }
```

- [ ] **Step 5: Run the tests**

Run: `npx playwright test tests/drift.spec.ts tests/print.spec.ts tests/a11y.spec.ts -g "drift|print|report"`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add web/app/globals.css web/app/print.css web/tests/drift.spec.ts
git commit -m "feat(web): drift diff highlights in, timeline hover, print kills motion

One keyframe (transparent → declared background) on the four diff rules;
glyph encoding untouched. print.css zeroes every animation/transition."
```

---

### Task 7: Full verification, bundle-size record, spec status

**Files:**
- Modify: `docs/superpowers/specs/2026-09-16-web-ui-redesign-design.md:4` (status line) and append a §8.
- Test: the whole suite.

- [ ] **Step 1: Full suite, type-check, lint**

Run from `web/`: `npx tsc --noEmit && npm run lint && npx playwright test`
Expected: every test PASSES — the pre-existing ones plus the 22 added by Tasks 1–6. Note the summary line (`N passed`) for the commit message below. If anything fails, fix it in the task that owns the file and re-run; do not proceed with a red suite.

- [ ] **Step 2: Bundle-size check (spec §5, last bullet)**

Build the branch, from `web/`:

```bash
npm run build 2>&1 | grep -E "First Load|/scans|^[┌├└] "
```

Record the `First Load JS` column for `/`, `/scans/[id]`, `/scans/[id]/findings`, `/scans/[id]/graph`, `/scans/[id]/drift`.

Build the baseline in a separate worktree so nothing in the working tree is touched (`c913d9f` is the last commit before this plan's work):

```bash
git worktree add ../ap-baseline c913d9f
cd ../ap-baseline/web && npm ci --silent && npm run build 2>&1 | grep -E "First Load|/scans|^[┌├└] "
cd - && git worktree remove ../ap-baseline
```

Expected: per-route increase ≤ 40 kB gzipped (motion's tree-shaken `motion/react` core is ~18 kB gz; the shared chunk carries it once). Record both numbers in the spec §8 below. If the increase exceeds 40 kB on any route, stop and report — do not tune the bundle in this task.

- [ ] **Step 3: Record in the spec**

Change line 4 of the spec to:

```
**Status:** implemented 2026-09-17 (plan `docs/superpowers/plans/2026-09-17-web-ui-redesign.md`)
```

Append to the spec:

```markdown
## 8. Implementation record (17 Sep 2026)

- `motion` 13.4.0 (MIT) added; all JS-driven entrances go through
  `web/src/lib/motion.ts`. Scan setup (§4.1) and drift (§4.5) turned out to
  need no JS motion at all and are pure CSS.
- Bundle impact (`next build`, First Load JS): before → after —
  `/` __ → __ kB · `/scans/[id]` __ → __ kB · findings __ → __ kB ·
  graph __ → __ kB · drift __ → __ kB.
- Playwright suite: __ passed (22 new: 2 live-scan entrance, 2 terminal
  frame, 5 scan setup, 4 findings, 6 graph, 3 drift), a11y matrix green
  on all six screens, tokens/print unchanged and green.
- Spec deviations: none. §4.3's "filter change" has no filter to attach
  to today; rows are keyed by id so a future filter gets the mount reveal
  for free.
```

Fill in every `__` from Steps 1–2 — a blank left in is a plan failure.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-09-16-web-ui-redesign-design.md
git commit -m "docs(spec): web UI redesign implementation record

Suite: <N> passed. Bundle: <summary of before → after>."
```

- [ ] **Step 5: Hand off**

Use `superpowers:requesting-code-review` on the branch, then `superpowers:finishing-a-development-branch`.
