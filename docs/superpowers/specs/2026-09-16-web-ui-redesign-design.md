# Agent Perimeter — Web UI visual polish + motion

**Date:** 16 September 2026
**Status:** design approved in brainstorming; awaiting implementation plan
**Scope:** the five Next.js screens under `web/app/**` (not the Python-rendered
static `report.html` artifact from `agent_perimeter/report/html.py`, which
`web/tests/a11y.spec.ts` also tests but this redesign does not touch).
**Consumes:** the existing design tokens (`web/app/globals.css`), fonts
(`web/app/layout.tsx`), and shared component library
(`web/src/lib/_bok-ui.tsx`) unchanged in substance — no accent/neutral/
severity/provenance color, radius, or font-family value changes.

---

## 1. Why

The app's design tokens are already deliberate and hard-won — a WCAG-AA-
fixed severity/provenance ramp, a warm-neutral paper/ink scale, a signal-
amber accent, three purposeful typefaces (Newsreader/Geist/IBM Plex Mono),
density modes, and a print stylesheet. What's missing is execution: spacing
and hierarchy read flatter than the token system implies, several
interactive elements (mode radios, scope-file dropzone, table rows, graph
nodes) are under-styled for hover/focus, and nothing animates — state
changes (a check streaming in, a row expanding, a tool's description
drifting) happen instantly with no visual continuity.

## 2. Decisions taken (brainstorming, 16 Sep 2026)

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | Visual identity | **Keep it, elevate execution.** Same accent, same neutral/severity palette, same three typefaces. Stitch was tried first for mockups (see §10); it stalled for 20+ minutes producing nothing and was abandoned. | A new palette/type system via Stitch or otherwise — would risk regressing the WCAG-AA contrast work already done and cost re-verifying against the fixed severity ramp. |
| D2 | Scope | **All five screens together**, so the motion/spacing system reads as one thing, not a patchwork. | Pilot on one screen first — rejected in brainstorming as unnecessary given how narrow the actual change is (spacing/hover/motion, not structure). |
| D3 | Motion budget | **Purposeful micro-interactions only**: hover/focus states, list-row reveal, graph node/edge entrance and hover, diff-line highlight, loading skeletons. No page transitions, no hero animation, no bounce/overshoot easing (explicitly wrong for dense data tables per the UX guidance pulled in brainstorming). | A fuller motion system (page transitions, hero animation, force-directed graph physics) — more surface area to keep accessible/performant for a security tool's restrained tone. |
| D4 | Motion library | **`motion`** (the MIT-licensed successor to Framer Motion) for anything that needs JS-driven staggering or `AnimatePresence`-style enter/exit; plain CSS transitions/`@keyframes` for simple hover/focus states, which already inherit the project's existing global `prefers-reduced-motion` rule (`globals.css:204-209`) for free. | GSAP — recommended by the `ui-ux-pro-max` skill's generic guidance, but its license is not Apache/MIT/BSD (CLAUDE.md's dependency floor), so it's disqualified regardless of fit. |
| D5 | Design-reference tooling | **`ui-ux-pro-max`'s local search** (motion timings/easing, UX/accessibility guidance, React performance patterns) for palette-agnostic guidance only. Its `--design-system` color/pattern output (a generic dark slate-and-green developer-tool palette, FAQ-page layout pattern) was explicitly discarded as off-target for this product — see D1. | Adopting the tool's design-system output wholesale. |

Routine calls made without asking: timing/easing numbers below are drawn
from the `ui-ux-pro-max` "Subtle" stagger-list tier (250–350ms,
`power1.out`-equivalent ease, ≤0.04s per-item stagger, capped total reveal
time) — the tier explicitly recommended against dense/informational UI
using overshoot easing; hover/focus transitions use the tool's stated
150–300ms range.

## 3. Correction from brainstorming

The design floated fixing a "clickable div, not a real button" accessible-
toggle anti-pattern. Checked against the actual code
(`web/src/lib/_bok-ui.tsx:114-149`, the `Claim` component): it is already a
`<span role="button" tabIndex={0}>` with correct `Enter`/`Space` handling,
`event.stopPropagation()` so it doesn't double-fire the parent
`FindingsTable` row's own click target, and a `.sr-only` derivation label —
the correct ARIA pattern for a button nested inside another interactive
row, which a real `<button>` cannot do without invalid HTML nesting. **No
accessibility fix is in scope here** — this item is dropped.

## 4. Per-screen design

### 4.1 Scan setup (`web/app/page.tsx`)
- Spacing: tighten the vertical rhythm between title/subhead/target
  field/mode selector/submit using the existing `--space-*` scale rather
  than ad hoc margins (audit whatever the current CSS uses).
- `ModeSelector`'s Active-mode lock: currently just disabled; add a hover
  state on the lock explanation itself (it's informational, not
  interactive, so no new tab stop) and a CSS transition when the lock
  state flips (scope file attached → unlocked) — background/border
  transition on the radio, 200ms, ease-out. No new component.
- `ScopeFileField` dropzone: hover/focus/drag-over states currently absent
  or minimal — add them (border color shift to accent, 150ms).
- Submit button: disabled→enabled transition (color/cursor, 150ms), and a
  pressed/loading state transition while `submitting` is true (existing
  state, just needs a visual treatment — a subtle pulse on the button
  label, not a spinner, matching `00 §5.5`'s "never a spinner" rule already
  followed by `Skeleton`).

### 4.2 Live scan (`web/app/scans/[id]/page.tsx`)
- `PhaseGroup` rows: as each check's `ScanEvent` arrives and a new row
  mounts, it enters via `motion.div` — opacity 0→1, y 8px→0, 300ms,
  `easeOut`, ≤40ms stagger between rows arriving in the same event batch
  (most arrive one at a time over the SSE-like stream already, so stagger
  rarely compounds).
- The pending-check `Skeleton` gets a CSS pulse animation (`@keyframes`,
  opacity 0.5↔1, 1.5s loop) instead of a static block.
- The terminal-frame transition (running → `EmptyState`/summary) gets a
  brief cross-fade (200ms) so the status region swap doesn't pop — must
  preserve the existing single-`role="status"`-at-a-time invariant the
  component's own comments document; the fade is opacity-only on the
  outgoing/incoming elements, never both mounted with a live region
  simultaneously.

### 4.3 Findings (`web/app/scans/[id]/findings/page.tsx`, `FindingsTable`)
- `ConformanceStrip` header: no motion (it's a static summary line), just
  spacing/weight polish.
- `FindingsTable` rows: reveal on mount and on filter-change via
  `motion.tr`-equivalent (rows are native `<tr>`; `motion` supports
  `as="tr"` or a wrapping strategy — implementation detail for the plan),
  opacity+y, 250–300ms, **`easeOut`, explicitly no spring/back overshoot**
  per the "don't use bounce on dense data tables" guidance. Must respect
  the existing `@tanstack/react-virtual` windowing — only mounted
  (currently-rendered) rows animate; the plan's implementation task
  verifies this doesn't fight virtualization's own recycling.
- Row expand/collapse (`FindingRow`'s reproduction + `EvidencePane`):
  height/opacity transition, 200ms, matching the existing
  `bok-row-expandable` class hook.
- `SeverityBadge`: hover state (subtle scale/brightness, 150ms) — decorative
  only, the glyph+label+color encoding is unchanged.

### 4.4 Capability graph (`web/app/scans/[id]/graph/page.tsx`, `CapabilityGraph`)
- Explicitly the flagship screen ("the signature moment" per the component's
  own comments) — gets marginally more presence than the others, still
  restrained: node entrance (opacity+scale 0.95→1, 300ms, staggered by
  graph layer/depth if the layout algorithm exposes one, else by array
  order capped at the same ≤40ms/item budget as §4.2).
- Edge derivation styling (schema/description/probe — already rendered
  differently per the design system's "never just colored" rule) gets a
  draw-in transition on entrance (stroke-dasharray reveal, 400ms) — SVG/
  Canvas-appropriate, whichever `CapabilityGraph` currently renders with
  (check before planning).
- Hover on a node highlights its connected edges (opacity dim on
  unconnected edges, 150ms) — this is new interaction, not purely visual;
  must not remove keyboard-reachability of the same information (the
  `ProvenanceRail` this screen already opens on node activation is the
  keyboard-accessible equivalent, unchanged).

### 4.5 Drift diff (`web/app/scans/[id]/drift/page.tsx`, `DiffView`, `RunTimeline`)
- `DiffView` lines: as the diff renders, added/removed lines highlight in
  (background-color transition from transparent to the existing
  addition/removal token, 300ms) — text itself (the +/− prefix, monospace)
  is unchanged and unaffected, since that's the non-color-dependent
  encoding the design system requires.
- `RunTimeline` events: minor hover state polish only, no entrance motion
  (it's a compact summary strip, not a list worth staggering).

## 5. Motion implementation rules (bind every task in the plan)

- Every JS-driven (`motion`) animation checks `useReducedMotion()` (or the
  equivalent `motion` API) and renders the final state immediately when
  true — the existing global CSS rule (`globals.css:204-209`) already
  covers pure-CSS transitions/animations for free, but does **not** cover
  `motion`'s WAAPI-driven animations, so this check is not optional.
- No animation may be the sole carrier of information — every state change
  it animates must already be legible in the static (reduced-motion) end
  state, matching the existing severity/provenance "glyph + label, never
  color alone" rule extended to motion.
- No easing with overshoot/bounce (`back.out`, spring with high stiffness)
  anywhere in the findings table or drift diff — editorial restraint per
  D1/D3. The capability graph may use a very slight settle (`easeOut` with
  a touch of `backOut(1.1)` at most) given its flagship status, never on
  the two data-dense screens.
- `motion` is a new dependency (MIT license, satisfies the Apache/MIT/BSD
  floor); no other new dependency is introduced. Bundle-size impact is
  checked in the plan's verification step (`motion`'s tree-shaken core is
  small, but this is stated, not assumed).

## 6. Testing

- The existing six-screen `a11y.spec.ts` matrix (five Next.js screens +
  the static `report.html`) must stay green — axe zero serious/critical,
  full keyboard reachability, visible focus ring — for every screen this
  redesign touches. `report.html` is untouched by this work and its test
  continues to pass unmodified.
- New Playwright coverage: for each animated interaction, one test
  asserting the end state is reached (not the animation's visual path,
  which is brittle) — e.g. a filtered findings table settles on the
  correct row set, an expanded finding row shows its reproduction command,
  a hovered graph node's connected edges are marked (via a class/attribute
  the test can query, not pixel inspection).
- One Playwright test per redesigned screen asserting the reduced-motion
  path: emulate `prefers-reduced-motion: reduce`
  (`page.emulateMedia({ reducedMotion: "reduce" })`), assert the same end
  states are reached immediately (no `waitForTimeout` needed for the
  reduced-motion run, which is itself evidence the check worked).
- `web/tests/tokens.spec.ts` (existing) must stay green — no token value
  changes.
- `web/tests/print.spec.ts` (existing) must stay green — motion is
  irrelevant to print, but any spacing changes must not break print
  layout.

## 7. Out of scope (recorded so nobody re-decides it by accident)

- The static `report.html`/`census.html` artifacts (`agent_perimeter/
  report/html.py`, `analysis/render_web_fixtures.py`) — Python-rendered,
  not part of the Next.js app, not touched.
- Any token value change (color, font, radius, spacing scale) — D1.
- Page-level transitions, hero animation, decorative motion beyond §4/§5 —
  D3.
- The `Claim` accessible-toggle "fix" floated in brainstorming — §3,
  already correct.
- GSAP or any non-Apache/MIT/BSD motion library — D4.
- Dark mode — the existing `@media (prefers-color-scheme: dark)` block
  (`globals.css:102`) is untouched; this redesign doesn't add or change
  dark-mode-specific rules beyond whatever spacing/motion changes apply
  identically in both modes.
