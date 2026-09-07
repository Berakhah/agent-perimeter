# Task 14 report — Screen 4: the capability graph

## What was implemented

- `web/app/scans/[id]/graph/page.tsx` — route (Client Component; `params`/`searchParams` are
  `Promise`s, unwrapped with `use()`). `?fixture=deputy|mixed-derivation|no-tools` replays
  `./fixtures.ts` synchronously in the render body (no `useEffect` gate) so a fixture run's first
  paint already carries the real graph — required because `tests/graph.spec.ts`'s keyboard test
  presses Tab immediately after `goto` with no wait for content. The real (non-fixture) path fetches
  both `getGraph(id)` and `getFindings(id)`, cross-referencing findings whose `check_id` starts
  `"policy."` (`claim.value` = the flagged tool's name) to build the flagged-tools set — ruling 1.
- `web/app/scans/[id]/graph/fixtures.ts` — `deputy` (confused-deputy: `sync_to_remote` has
  fs_read+net_out, schema+probe derived, policy-flagged; `list_files` unflagged and ordered first),
  `mixed-derivation` (schema/description/probe/artifact edges, deliberately no `name`-derived edge —
  the RED regex excludes it), `no-tools` (empty).
- `web/app/components/CapabilityGraph.tsx` — the bipartite SVG graph (tool nodes left, the 7 fixed
  `Capability` nodes right) plus the always-visible accessible `<table caption="Capability edges">`
  (one row per edge), built from one shared, edge-ordered list so tool tab order and table row order
  can't drift apart. `FlaggedToolNode` owns the one-shot pulse (`data-pulse`: pending→playing→done via
  a real CSS `onAnimationEnd`, or straight to `skipped` under `prefers-reduced-motion` via
  `useLayoutEffect` + `window.matchMedia`, never visibly passing through "playing"). Derivation maps
  to a distinct SVG `stroke-dasharray` per edge plus a legend built from `_bok-ui.tsx`'s
  `DERIVATION_META`.
- `web/app/components/EdgeTooltip.tsx` — shows "why" (derivation + rationale) for whichever edge is
  hovered or focused; a fixed panel rather than a floating cursor-tooltip, sidestepping SVG-viewBox
  vs CSS-pixel coordinate math this small static layout has no other reason to need.
- `web/src/lib/_bok-ui.tsx` — exported `DERIVATION_META` (was module-private) for the legend to reuse.
- `web/src/lib/api.ts` — added `Capability` + `CapabilityEdge` types (matching
  `agent_perimeter/model/edge.py` field-for-field) and narrowed `getGraph()` from `Promise<unknown[]>`
  to `Promise<CapabilityEdge[]>`.
- `web/tests/graph.spec.ts` — verbatim 7-test RED file from the brief.

## Node/edge testid convention

Only tool nodes are interactive/focusable and carry `data-testid`. **Unflagged** tools:
`data-testid="node"`. **Flagged** tools: `data-testid="node-flagged"` exclusively (not also
`"node"`, since Playwright's `getByTestId` is an exact-match CSS attribute selector — a single
element can't satisfy both). The `deputy` fixture deliberately orders `list_files` (unflagged)
before `sync_to_remote` (flagged) so `getByTestId("node").first()` resolves to a real, focusable
element and the single-Tab-press test is unambiguous. Capability nodes are non-interactive (no
tabIndex) and edges are rendered last in DOM/tab order so a first Tab press always lands on a tool
node.

## TDD evidence

**RED** (`npx playwright test tests/graph.spec.ts` before the route existed): 6 failed for the
expected reason (route/elements not found), 1 vacuously passed (the `for` loop over
`getByTestId("edge").all()` is empty on a 404 page, so its body never executes — a known,
harmless quirk of that assertion shape, not something to "fix" at RED).

**GREEN**: after building all files, `npx playwright test tests/graph.spec.ts` → 7/7 passed. One
real bug found and fixed during GREEN: the fixture-loading path originally used `useState` +
`useEffect` (mirroring Task 13's findings page), which left a one-render gap where the Skeleton
(no focusable content) was still showing when the RED test's blind `Tab` press (no wait) arrived —
`document.activeElement` was `body`. Fixed by computing fixture data directly in the render body
(no effect, no async gap) so a fixture run's very first commit already contains the real,
focusable graph.

**Double-run flakiness check** (explicitly requested for the pulse-timing test): `npx playwright
test tests/graph.spec.ts --repeat-each=5` → 35/35 passed. Re-verified later against a production
build with `--repeat-each=8` → 56/56 passed.

**Full suite**: `npx playwright test` (all 6 spec files, 30 tests) → 30/30 passed on the first run.

## A real flake found during self-review, diagnosed, and resolved

While self-reviewing, later re-runs of the *full* suite (`npx playwright test`, all 30 tests, 11
parallel workers) intermittently failed exactly one assertion: "the graph is fully navigable from
the keyboard"'s second half (Enter → rail visible), timing out even though the first half (Tab →
node focused) always passed. Investigation:

- Isolated `graph.spec.ts` runs (7/7, then 35/35 with `--repeat-each=5`) never reproduced it.
- A duplicate diagnostic spec running the identical steps (Tab, check focus, Enter, inspect
  `provenance-rail`'s `aria-hidden`/`inert` and `document.activeElement` via `page.evaluate`)
  **passed** even in the same full-suite run where the real test failed in a different worker —
  ruling out a logic bug in the activation handler itself.
- Rebuilt (`next build`) and ran the full suite against `next start` (production) instead of
  `next dev`: 31/31 passed in 4.3s total (vs. 20–35s under dev mode), and repeated 56/56 clean.

Conclusion: this was `next dev`'s on-demand route compilation contending under 11-way parallel
first-hit load (a cold dev-server compiling `/scans/[id]/graph` while ~30 other page loads compile
simultaneously), not an application bug — the same tradeoff `playwright.config.ts`'s own existing
ponytail comment already flags ("switch `command` to `npm run build && npm run start` if a future
test needs production-only behaviour"). No test or app-code change was made to "fix" this, since
the evidence points at infrastructure, not logic; flagging it here rather than silently re-running
until green.

## Self-review finding, fixed

The outer `<svg>` initially carried `role="img"`, which per ARIA authoring practices flattens an
element's descendants into a single opaque image for assistive tech — wrong here since the graph
has real focusable, activatable descendants (tool nodes, edges). Removed in a follow-up commit;
re-ran `tests/graph.spec.ts` (7/7) and lint afterward to confirm no regression.

## Verification

- `npx tsc --noEmit` — clean.
- `npx eslint` on all new/touched files — clean.
- `npx next build` — succeeds; `/scans/[id]/graph` listed as a dynamic route.

## Files changed

- Created: `web/app/scans/[id]/graph/page.tsx`, `web/app/scans/[id]/graph/fixtures.ts`,
  `web/app/components/CapabilityGraph.tsx`, `web/app/components/EdgeTooltip.tsx`,
  `web/tests/graph.spec.ts`
- Modified: `web/src/lib/_bok-ui.tsx` (exported `DERIVATION_META`), `web/src/lib/api.ts` (added
  `Capability`/`CapabilityEdge`, narrowed `getGraph`), `web/app/globals.css` (Screen 4 styles: node/
  edge/pulse/ring/tooltip/legend/table)

## Commits

- `1812f75` — feat: capability graph with per-edge derivation and a single pulse
- `7d285cc` — fix: drop role=img from the capability graph's svg (self-review catch)

## Concerns / things worth a second look

1. The dev-server-cold-start flakiness described above is real and reproducible under enough
   parallel load; it isn't specific to this task's code (confirmed via the diagnostic spec and the
   production-build re-run) but it's worth knowing it exists if CI ever runs the whole suite under
   `next dev` with high worker counts. `playwright.config.ts` already anticipates the fix (switch to
   `next build && next start`) if this becomes a recurring problem.
2. The force-directed layout is a static two-column bipartite layout (tools left, capabilities
   right), not a real force simulation — explicitly permitted by the dispatch ("hand-rolled simple
   layout is fine"); marked with a `ponytail:` comment in `CapabilityGraph.tsx` naming the upgrade
   path if a much larger graph ever needs organic clustering.
3. `EdgeTooltip` is a fixed panel below the canvas rather than a floating cursor-following tooltip —
   a deliberate simplification (avoids SVG-viewBox-to-CSS-pixel scaling math this small, static
   layout doesn't otherwise need) noted in the component's own doc comment.
