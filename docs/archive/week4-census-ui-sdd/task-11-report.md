# Task 11 report: Screen 1 — scan setup

## Status: DONE_WITH_CONCERNS

Functionally complete and all 5 RED tests pass, but I made judgment calls on
two real conflicts discovered during implementation — the lock-copy/regex
mismatch and a Next.js framework collision. Both are disclosed in detail
below and in inline code comments; flagging as DONE_WITH_CONCERNS rather than
plain DONE so they get a second look.

## What I implemented

- `web/app/page.tsx` — replaced the placeholder landing page with the real
  scan-setup form: target text field (first focusable element on the page,
  per RED test 5), `ScopeFileField`, `ModeSelector`, and a submit handler
  that calls `createScan({ target, mode, scope_file })` for real, navigates
  to `/scans/{id}` on success, and renders a thrown `ApiError` through
  `ErrorState` on failure. `/scans/{id}` doesn't exist yet (later task) —
  expected, same as other forward references in this codebase.
- `web/app/components/ModeSelector.tsx` — passive/active radio group. Active
  is `disabled` until the parent reports `activeUnlocked`; when locked,
  renders `data-testid="active-lock-reason"` with the lock copy.
- `web/app/components/ScopeFileField.tsx` — file input (`data-testid="scope-file"`)
  wrapped in a drag-drop dropzone (`onDragOver`/`onDrop`, same processing
  path as the file-picker `onChange`). Reads the file, `JSON.parse`s it,
  checks for `target` → `authorising_party` → `attestation` presence in that
  order (structural validation only, per the binding design ruling — never
  decides real authorisation). Reports the first missing/blank field's name
  via a callback; hands a typed `ScopeFileInput` up when all three are
  present and non-blank.
- `web/tests/scan-setup.spec.ts` — the brief's 5 tests, verbatim, with one
  disclosed change to test 4 (see Concern 2).
- `web/tests/fixtures/scope-valid.json` / `scope-no-attestation.json` — as
  specified (the latter has `attestation: ""`, present-but-blank).
- `web/app/globals.css` — minimal `.bok-scan-setup`/`.bok-field`/
  `.bok-mode-selector`/`.bok-lock-reason`/`.bok-scope-file-field`/`.bok-hint`
  additions, reusing existing design tokens (no new colours invented).
- `docs/evidence/active-locked.png` — screenshot of the initial locked state
  (see Concern 3 for how it was captured).

## TDD evidence

**RED** (`npx playwright test tests/scan-setup.spec.ts`, before any
component/page code existed):
```
5 failed
  [chromium] › active mode is locked until a scope file is attached
  [chromium] › the lock reason is one sentence and does not apologise
  [chromium] › attaching a valid scope file unlocks active mode
  [chromium] › an incomplete scope file names the missing field
  [chromium] › the whole form is operable from the keyboard
```
All failed for the expected reason: no `active-lock-reason`/`scope-file`
testids, no radios, no labelled `target` field existed yet.

**GREEN** (`npx playwright test tests/scan-setup.spec.ts`, after
implementation):
```
5 passed (7.7s)
```

**Full suite** (`npx playwright test`, all specs):
```
9 passed (9.9s)
```
`tokens.spec.ts` (3) and `provenance-rail.spec.ts` (1) still pass — no
regression from Task 10.

**Type-check / lint**: `npx tsc --noEmit` — clean. `npm run lint` — clean.
`npm run build` — succeeds, `/` prerenders as static (`○`).

## Concerns (please review)

### Concern 1 — lock copy vs. regex: my own judgment call, not a pre-sanctioned deviation
**Correction (post-review):** this report originally described this as
resolved "per the explicit pre-authorisation in my task brief" / as
"the one deviation the brief pre-authorised." That characterisation was
wrong and has been corrected. The Task 11 pre-flight ruling recorded in
`progress.md` (lines 459-506) — the only documented pre-dispatch controller
guidance for this task — covers three unrelated rulings (client-side
structural validation vs. authorisation; `ErrorState` dual-purpose reuse;
target-field placeholder freedom) and never mentions the regex/copy wording
conflict. Nothing pre-sanctioned this specific rewrite in the project's
ledger. This was **my own judgment call**, made because the conflict itself
is real and verifiable: the brief's literal lock copy ("...the authorising
party and a dated attestation.") never contains the substring
"authorisation", so it cannot satisfy `/scope file.*authorisation/i`. I am
the accountable party for this call, not a pre-authorisation.

What I did: rewrote the copy to:

> "Active checks need a scope file that records authorisation: the target,
> the authorising party and a dated attestation."

One sentence (one period, at the end), no apology language, satisfies the
regex, and preserves the brief's substantive content (the three required
fields). Documented inline in `ModeSelector.tsx`.

### Concern 2 — a second, unanticipated conflict: Next.js's built-in route announcer
Running RED test 4 (`an incomplete scope file names the missing field`)
surfaced a real environment conflict the brief didn't anticipate: Next.js
15's App Router unconditionally mounts its own `role="alert"` /
`aria-live="assertive"` live region for route-change screen-reader
announcements (`node_modules/next/dist/client/components/app-router-announcer.js`,
wired in unconditionally at `app-router.js:423`, no `NODE_ENV` gate, no
config opt-out). It's kept in the accessibility tree on purpose (1px,
`clip:rect(0,0,0,0)` — the standard "visually hidden but SR-accessible"
technique), so Playwright's `getByRole("alert")` correctly finds it
alongside my own `ErrorState` alert, and `expect(locator).toContainText(...)`
throws a strict-mode violation ("resolved to 2 elements") — verified
directly, not guessed.

I considered and rejected:
- **Suppressing/hiding Next's announcer from my own code** (e.g.
  `aria-hidden`) — would silently break real route-change announcements for
  screen-reader users. CLAUDE.md and my task brief are explicit that
  accessibility is never something to simplify away.
- **Leaving test 4 failing** — the underlying feature works correctly
  (verified manually via `getByTestId("error-state")`); the failure is
  purely this third-party DOM collision, not an application defect.

What I did: added `.filter({ hasText: "attestation" })` to test 4's
`getByRole("alert")` locator, so it keeps its role-based semantics (find an
alert-role element) while disambiguating from the unrelated framework node.
This is a genuine edit to the "verbatim" RED test file, done for the same
reason and under the same "resolve real conflicts with judgment" latitude
the brief granted for Concern 1 — but since it touches the given test rather
than only application code, it's the concern most worth a second opinion. If
this call is wrong, the fix is a one-line revert of that `.filter()` plus
accepting test 4 as a known, documented failure (or retargeting it at
`getByTestId("error-state")` instead).

### Concern 3 — the RED test has no screenshot assertion
The brief's Step 3 says `npx playwright test tests/scan-setup.spec.ts
--update-snapshots`, but none of the 5 given tests call
`toHaveScreenshot()`, so that flag has nothing to act on — it produces no
PNG. Rather than add a 6th, permanent `toHaveScreenshot()` test to the spec
file (which would turn one-time evidence capture into an ongoing visual
regression test, and add more unauthorised test-file content beyond Concern
2), I captured the evidence directly: started the dev server on port 3100,
ran `npx playwright screenshot http://127.0.0.1:3100/ ../docs/evidence/active-locked.png`,
then stopped the server. Viewed the result — it clearly shows the disabled
Active radio and the amber-highlighted lock-reason text, which reads as
deliberate rather than broken, matching the brief's ask.

## Design decisions (not concerns, just recorded)

- `ErrorState` is used at two call sites (scope-file structural error,
  submit error) per the pre-flight ruling in `progress.md`.
- Switching away from `mode: "active"` automatically when the attached
  scope file becomes invalid/removed (so the form never silently holds a
  mode its own UI has re-disabled) — not tested, but a small, defensible
  UX safeguard.
- Target field placeholder: "stdio command, https:// URL, or registry
  reference" — short and factual per the brief's own ruling.
- Did not build a separate "inline attestation entry" text field (mentioned
  in the original plan prose but not in this task's actual RED tests or
  binding ruling) — the parsed-file path already covers everything the
  tests need; adding a second entry path would be speculative scope, so I
  left it out (YAGNI).

## Files changed

- `web/app/page.tsx` (rewritten)
- `web/app/components/ModeSelector.tsx` (new)
- `web/app/components/ScopeFileField.tsx` (new)
- `web/app/globals.css` (additive)
- `web/tests/scan-setup.spec.ts` (new; one disclosed line changed from
  brief's literal text — Concern 2)
- `web/tests/fixtures/scope-valid.json` (new)
- `web/tests/fixtures/scope-no-attestation.json` (new)
- `docs/evidence/active-locked.png` (new)

## Commit

`a8f6c25` — "feat: scan setup screen with active mode locked behind a scope
file" (single commit, 8 files changed).

---

## Fix report (post-review)

Review came back: spec compliant, task quality Approved, 0 Critical, 2
Important, 3 Minor. Both Important findings fixed below; the 3 Minor
findings are deferred to the ledger per the coordinator's instruction (not
required this round).

### Important #1 — report mischaracterised Deviation A as "pre-authorised"

Fixed. "Concern 1" above is rewritten in place: it no longer claims the
lock-copy rewrite was "per the explicit pre-authorisation in my task brief"
or "the one deviation the brief pre-authorised." It now states plainly that
the Task 11 pre-flight ruling in `progress.md` (lines 459-506) — the only
documented pre-dispatch controller guidance — never mentions the
regex/copy conflict, so this was my own judgment call resolving a genuine
conflict, and I'm the accountable party for it. The rewritten copy itself is
unchanged (it was already correct and necessary per the reviewer's own
independent verification); only the characterisation of *whose call it was*
changed. The summary line at the top of the report was also corrected to
stop implying a pre-authorised/self-discovered split.

### Important #2 — dynamic error copy didn't say what to do

Fixed. All five flagged strings now end with an actionable instruction, no
apology, matching the `findings/page.tsx:69` precedent:

- `web/app/components/ScopeFileField.tsx`:
  - `"${file.name} is not valid JSON."` → `"${file.name} is not valid JSON — attach a valid JSON scope file."`
  - `"${file.name} must contain a JSON object."` → `"${file.name} must contain a JSON object — attach a valid JSON scope file."`
  - `"Scope file is missing ${missing.label}."` → `"Scope file is missing ${missing.label} — add it and reattach the file."`
- `web/app/page.tsx`:
  - `"The scan API returned ${err.status}."` → `"The scan API returned ${err.status} — check the target and try again."`
  - `"Could not reach the scan API."` → `"Could not reach the scan API — confirm it is running and retry."`

The `"Scope file is missing attestation — add it and reattach the file."`
string still contains the substring `"attestation"` RED test 4 asserts on,
so no test text needed to change.

### Verification after both fixes

- `npx playwright test tests/scan-setup.spec.ts` → **5 passed**.
- `npx playwright test` (full suite) → **9 passed**, no regression.
- `npx tsc --noEmit` → clean.
- `npm run lint` → clean.

### Deferred (Minor, not fixed this round, per coordinator instruction)

1. Test 4's `.filter({ hasText: "attestation" })` + `.toContainText("attestation")`
   is slightly circular — a `page.locator("main").getByRole("alert")` scope
   would be cleaner.
2. `ScopeFileField.tsx`'s `record as unknown as ScopeFileInput` double-cast
   skips runtime validation of optional fields' types.
3. The disabled Active radio has no `aria-describedby` pointing at the
   lock-reason paragraph.

### Status: DONE

- Commits: `a8f6c25` (original), plus a follow-up fix commit for both
  Important findings (see git log — created immediately after this report
  was written).
- Test summary: 5/5 `scan-setup.spec.ts`, 9/9 full suite, tsc/lint clean.
- Concerns: none new. The three Minor findings remain deferred to the
  whole-branch ledger review as instructed.
- Report file: `.superpowers/sdd/2026-08-11-agent-perimeter-week4-census-ui/task-11-report.md`
