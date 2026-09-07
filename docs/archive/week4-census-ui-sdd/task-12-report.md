# Task 12 report: Screen 2 — live scan

## Status: DONE_WITH_CONCERNS

Functionally complete, all 5 RED tests pass reliably (3 consecutive runs,
full suite twice), but I made one disclosed edit to the brief's "verbatim"
RED test file to resolve a genuine, deterministic accessibility-role
collision the brief's own ruling anticipated and pre-authorised a fallback
for. Flagging as DONE_WITH_CONCERNS so it gets a second look, per the same
convention Task 11 used for its own disclosed test-file edit.

## What I implemented

- `web/app/scans/[id]/page.tsx` — Client Component page (`params`/
  `searchParams` unwrapped with React's `use()`, since a Client Component
  can't `await` them the way `findings/page.tsx`'s async Server Component
  does). Subscribes to the real `subscribeToScanEvents` in production, or
  (when `?fixture=` is present) to a local `replayScanEvents` that shares
  its exact `(id, onEvent, onError?) => unsubscribe` signature and dispatches
  each canned event on a real `setTimeout` cadence (30ms per check, +500ms
  before the terminal frame). Renders: an `aria-live="polite" role="status"`
  progress line ("n of total checks complete") while the run is in flight,
  swapped — never shown alongside — for an `EmptyState` terminal summary
  ("No findings for the checks that ran" + skipped count, per the binding
  copy rule) once the terminal frame arrives; checks grouped by phase via
  `PhaseGroup`; a single `Skeleton` while any runnable check is still
  pending; and a `QuotaStrip` gated on whether `descriptions.llm_judge` (the
  only check the determinism budget lets call a model) has been observed in
  the arrived-event stream.
- `web/app/components/PhaseGroup.tsx` — new component. `role="group"` +
  `aria-labelledby` (pointing at an `<h2>{phase}</h2>`) gives each phase
  section an accessible name equal to the phase string. Each check —
  including a skipped one, reconstructed from the terminal frame's
  `skipped[]` array, since skipped checks never arrive as individual
  `ScanCheckEvent` frames (`scan_runner.py`: `completed` only increments for
  runnable checks) — renders as a `data-testid="check-row"` `<li>`.
- `web/app/scans/[id]/fixtures.ts` — three canned `ScanEvent[]` sequences.
  30 real check ids (from the brief's namespace list, minus
  `descriptions.llm_judge`) cover every phase; `revision` alone contributes
  11, so any 29-slice keeps at least one `revision` row.
  - `streaming`: 29 checks, all pass, terminal `skipped: []`.
  - `degraded`: 28 checks pass, 1 (`descriptions.llm_judge`) reported only
    in the terminal frame's `skipped` array, `reason: "model_unavailable"`,
    `detail` containing "no model provider".
  - `deterministic`: 29 checks, none of them `descriptions.llm_judge`, so
    the model lane never engages and `QuotaStrip` never renders.
- `web/app/globals.css` — additive `.bok-live-scan`/`.bok-phase-group`/
  `.bok-check-row`/`.bok-scan-progress` rules, reusing existing tokens (no
  new colours).
- `web/tests/live-scan.spec.ts` — the brief's 5 tests, with one disclosed
  line changed (see Concern below).

## TDD evidence

**RED** — with `web/app/scans/[id]/` and `PhaseGroup.tsx` temporarily moved
aside (`npx playwright test tests/live-scan.spec.ts`):
```
4 failed
  [chromium] › checks stream in grouped by phase
  [chromium] › no spinner is ever rendered
  [chromium] › skipped checks are shown with a reason, not omitted
  [chromium] › progress is announced to assistive technology
1 passed (quota-strip-absent — vacuously true on a 404 page)
```
All failed for the expected reason (`element(s) not found` — no route).
Files restored before continuing.

**GREEN**, before the locator fix (see Concern): 4/5 passed, 1 failed with
a **strict-mode violation**, not a timeout — `getByRole("status")` resolved
to 2 elements (my progress `<p>` and `Skeleton`'s own `role="status"`) and
`toContainText` failed in ~650ms–2.7s, not at the 5s timeout. Reproduced
identically under both 5 workers and `--workers=1`, ruling out worker
contention as the cause.

**GREEN**, after the locator fix, run 3 times consecutively
(`npx playwright test tests/live-scan.spec.ts`):
```
5 passed (4.0s)
5 passed (3.8s)
5 passed (3.8s)
```

**Full suite** (`npx playwright test`, all 4 spec files, run twice):
```
14 passed (5.9s)
14 passed (3.7s)
```
`tokens.spec.ts` (3), `provenance-rail.spec.ts` (1), `scan-setup.spec.ts`
(5) all still pass — no regression.

**Type-check**: `npx tsc --noEmit` — clean.
**Lint**: `npm run lint` — clean (0 errors, 0 warnings).
**Build**: `npm run build` — succeeds; `/scans/[id]` compiles as a dynamic
(`ƒ`) route, as expected for a per-scan page.

## Concern — one disclosed edit to the "verbatim" RED test

Ruling 2 anticipated a *pacing* race between the pending-check `Skeleton`
(bok-ui, always `role="status"`) and my own `aria-live` progress region
(also `role="status"`), and pre-authorised, as a fallback, scoping the
Playwright locator (the same way Task 11 did for Next's route announcer)
if a genuine unavoidable collision surfaced.

What I found in practice was stronger than a race: **Playwright's
`toContainText` fails immediately on a strict-mode violation — it does not
retry through it.** I verified this directly: the failing run's final
captured state was still "Starting scan…" (the pre-first-event state), and
the failure landed in 650ms–2.7s, far short of the 5s timeout, identically
whether run with 5 workers or `--workers=1` (ruling out CPU contention as
an alternate explanation). Since my page's very first render — before any
check has streamed in — legitimately has two `role="status"` elements at
once (the progress line showing "Starting scan…", and `Skeleton` since
nothing is resolved yet), no amount of pacing the *later* stream can help:
the collision exists at t=0, before the assertion's first (and only,
non-retried) evaluation.

Per ruling 2's own fallback, I narrowed test 5's locator:
```diff
- await expect(page.getByRole("status")).toContainText(/\d+ of 29/);
+ await expect(page.getByRole("status").filter({ hasText: /of/ })).toContainText(/\d+ of 29/);
```
`Skeleton` renders no text at all (just empty placeholder `<div>`s), so the
filter deterministically excludes it without touching either component's
real accessibility semantics — the same disambiguation-by-filter pattern
`scan-setup.spec.ts` already uses for Next's own route announcer. I did not
weaken the regex, remove `role="status"` from anything, or hide `Skeleton`
from assistive tech; the only change is which of the (legitimately, always
two, at various points) `role="status"` elements the test targets.

If this call is wrong, the alternative is to accept a permanent, by-design
failure on this one assertion (not a flaky one — it fails every time, for
the reason above) unless `Skeleton`'s or the progress region's
`role="status"` is removed, which ruling 2 explicitly forbids.

## A second bug caught and fixed along the way (not a design concern)

While first wiring GREEN, `fixtures.ts`'s doc comment contained the literal
substring `agent_perimeter/checks/*/*.py` — the `*/` inside that glob
closed the enclosing `/** ... */` JSDoc comment early, leaving `*.py`
outside it as invalid syntax and producing a hard 500 on `/scans/[id]`.
Reworded the comment to avoid an embedded `*/` (`the Python modules under
agent_perimeter/checks`, no glob). Caught via `curl` against a manually
started dev server plus the terminal's own SWC parse-error output, not
guessed.

## Design decisions (not concerns, just recorded)

- `QuotaStrip` renders a placeholder single-provider entry
  (`ponytail:` comment in `page.tsx`) when `descriptions.llm_judge` is
  observed running — `ScanEvent` carries no real provider-quota numbers on
  the wire today, so there is no live telemetry to show; this just proves
  the "model lane engaged" signal is real and wired, pending real numbers
  from the backend.
  - `RunTimeline` — not used, per ruling 3's explicit permission; building
  a second, fully redundant chronological view of the same 29 checks with
  zero test coverage would be pure duplication.
- Kept the fixture data in its own `fixtures.ts` module rather than inline
  in `page.tsx` (unlike `findings/page.tsx`'s small 5-row inline
  `FIXTURES`) — three 29-check sequences is a meaningfully larger data
  blob, and separating it keeps `page.tsx` focused on subscription/render
  logic.

## Files changed

- `web/app/scans/[id]/page.tsx` (new)
- `web/app/scans/[id]/fixtures.ts` (new)
- `web/app/components/PhaseGroup.tsx` (new)
- `web/app/globals.css` (additive)
- `web/tests/live-scan.spec.ts` (new; one disclosed line changed from the
  brief's literal text — see Concern above)

## Commit

`371bdba` — "feat: live scan screen with skeletons and visible skipped
checks" (single commit, 5 files changed, 444 insertions).

## Self-review

- Re-read both new component files and the fixtures module end to end
  after the lint/build pass; no leftover debug code, no stray `console.log`
  (a temporary standalone debug script used for diagnosis lived in the
  scratchpad / a throwaway `web/debug-scan.mjs`, both removed, neither
  committed — confirmed via `git status`).
- Checked for other accidental `*/`-inside-comment occurrences across the
  new files (`grep '\*/'`) — only the two legitimate comment terminators
  remain.
- `test-results/` (Playwright's own artifact directory from this session's
  RED/debug runs) is already covered by `web/.gitignore` (`/test-results/`)
  and never appeared in `git status` — nothing to clean up there.

## Concerns summary

1. One disclosed, ruling-pre-authorised edit to `live-scan.spec.ts` (locator
   scoping on test 5) — detailed above, please review.
2. `QuotaStrip`'s placeholder provider data is a known, commented gap
   (`ponytail:`) pending real quota telemetry on the wire — not tested,
   not required to be real by any RED test, flagged for visibility.

Report file: `.superpowers/sdd/2026-08-11-agent-perimeter-week4-census-ui/task-12-report.md`

---

## Fix report (post-review)

Review came back: spec compliant, task quality Approved, 0 Critical, 2
Important, 2 Minor. Both Important findings fixed below. One Minor
(doubled "Skipped —" prefix) and the stale "11" check-count comment were
also trivial one-line fixes, so I fixed both rather than deferring them;
the second Minor (documentation nit, no code impact) was already the
"skip unless trivial" case and is left to the ledger.

### Important #1 — `QuotaStrip` could show fabricated data in real mode

Fixed. `page.tsx`'s render condition changed from `modelEngaged &&
<QuotaStrip .../>` to `modelEngaged && fixture && <QuotaStrip .../>` — a
real (non-fixture) scan now renders nothing for `QuotaStrip` regardless of
whether `descriptions.llm_judge` engages, since there is no real quota
telemetry on the `ScanEvent` wire shape to show. The placeholder-data
`ponytail:` comment above `PLACEHOLDER_PROVIDERS` was extended to record
the gating explicitly, and a comment at the render site states the
invariant directly ("a real scan must never show invented numbers").

### Important #2 — no error handling on the real SSE path

Fixed. `subscribeToScanEvents(id, handleEvent)` now passes a third
argument: `() => setConnectionError(true)`. Added `connectionError` state
(reset at the top of the subscription effect, alongside the existing
per-navigation resets) and a `retryCount` state that's in the effect's
dependency array; when `connectionError` is true, the page renders
`ErrorState` (imported from `_bok-ui`) with `onRetry={() =>
setRetryCount((n) => n + 1)}`, which re-runs the whole subscription effect
— cleaning up the old (already-closed) `EventSource` and opening a fresh
one via `subscribeToScanEvents`. `replayScanEvents` (the fixture path)
still never calls `onError` (a canned replay has nothing to error about),
so `retryCount`/`connectionError` are only ever touched on the real path,
matching the report's original claim that this branch is "wired for
production" — now actually true end-to-end, not just structurally present.

`ErrorState` renders `role="alert"`, not `role="status"`, so it doesn't
interact with the `role="status"` disambiguation work from the original
report (RED test 5, `Skeleton` vs. the progress announcer) — verified by
re-running the full covering suite after the change.

### A real regression scare that turned out to be environmental, not code

After making both fixes, `npx playwright test tests/live-scan.spec.ts`
failed 4/5 — but the failures were the *original* pre-terminal states
(`element(s) not found`, `Received: 0`), not anything related to the two
fixes. A standalone Playwright script hitting the dev server directly
showed the page working correctly end to end (all 29 rows, correct
`role="status"` transitions, correct timing). The actual cause: a dev
server from an *earlier* test invocation was still listening on port 3100
(`playwright.config.ts`'s `reuseExistingServer: !process.env.CI` keeps it
alive across separate `npx playwright test` calls in a local/non-CI
session), and something about how it picked up the edits via Next's Fast
Refresh left it in a bad state for concurrent-worker requests, even though
a fresh single-page load against the same running instance looked fine.
Killing that stale process (`taskkill`) and letting Playwright's
`webServer` start a brand-new instance made the failure disappear
immediately and reproducibly (2 clean runs). Not a real code regression —
recorded here because it's a sharp edge worth knowing about for anyone
re-running this suite locally mid-session after editing files the
dev server has already compiled.

### Verification after both fixes

- `npx tsc --noEmit` → clean.
- `npm run lint` → clean (0 errors, 0 warnings).
- `npx playwright test tests/live-scan.spec.ts`, run twice on a fresh dev
  server → **5 passed** both times.
- `npx playwright test` (full suite) → **14 passed** (all of
  `live-scan.spec.ts`, `scan-setup.spec.ts`, `provenance-rail.spec.ts`,
  `tokens.spec.ts`).

### Files changed (this round)

- `web/app/scans/[id]/page.tsx` — `QuotaStrip` fixture-gated; `ErrorState`
  imported and wired to a new `connectionError`/`retryCount` state pair;
  doc comment updated.
- `web/app/scans/[id]/fixtures.ts` — removed the doubled "Skipped —"
  prefix from the `degraded` fixture's `detail` string; corrected the
  `revision` check-count comment (11 → 12).

### Commit

`18440e0` — "fix: gate QuotaStrip on fixture mode and wire SSE connection
errors" (2 files changed, 32 insertions, 10 deletions).

### Status: DONE

- Commits: `371bdba` (original), `18440e0` (this fix round).
- Test summary: 5/5 `live-scan.spec.ts` (×2 fresh runs), 14/14 full suite,
  tsc/lint clean.
- Concerns: none new beyond the original report's disclosed test-5 locator
  edit (already independently verified by the reviewer as the minimal
  correct fix) and the now-resolved `QuotaStrip` placeholder-data gap. The
  remaining deferred Minor (documentation nit on check-count wording in
  the *report*, not the code) is left to the whole-branch ledger as
  instructed.
- Report file: `.superpowers/sdd/2026-08-11-agent-perimeter-week4-census-ui/task-12-report.md`
