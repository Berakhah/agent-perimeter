# Task 13 report: Screen 3 — findings, with the revision conformance strip

## What was implemented

- `web/tests/findings.spec.ts` — the brief's 8 RED tests, verbatim.
- `web/src/lib/_bok-ui.tsx` (**modified**, per pre-flight ruling 4):
  - `FindingsTableRow` gained four optional fields: `cwe`, `taxonomyRefs`,
    `reproduction`, `evidence` (typed via the existing `EvidencePaneProps`).
    Optional so the pre-existing `/findings` fixture route (Task 10) still
    type-checks and renders unchanged.
  - `FindingsTableProps` gained two optional callbacks: `onClaimActivate?:
    (row) => void` (wraps the title cell in an interactive `<Claim>` only
    when supplied) and `renderExpanded?: (row) => ReactNode` (a per-row
    expansion slot rendered in a following `<tr>`).
  - Two new always-visible columns, `CWE` and `Taxonomy` (`data-testid="cwe"`
    / `"taxonomy"`), appended after `Confidence`.
  - Row click (guarded against bubbling from the embedded `Claim`, a
    `<button>`, or the column-resize handle) and Enter/Space on any focused
    cell both toggle row expansion when `renderExpanded` is supplied.
  - `toCsv()`'s header is now built from a separate `CSV_COLUMNS` array
    (`"provenance"`, lowercase) decoupled from the on-screen `FINDINGS_COLUMNS`
    (`"Provenance"`, capitalised) — ruling 2's case-sensitivity gotcha was
    real: verified directly, the old code reused `FINDINGS_COLUMNS` verbatim
    for the CSV header and would have failed the RED CSV test.
- `web/app/components/ConformanceStrip.tsx` (new) — the three numbers exactly
  per ruling 3: claim = `revision_claimed`; observed = |`features_observed` ∩
  the claimed revision's real 2026-07-28 (7-feature) or 2025-11-25
  (4-feature) bundle|; "of N" = that bundle's size; gaps = count of findings
  with `check_id === "revision.conformance_mismatch"`. Null/absent
  `revision_claimed` renders "revision unknown", never "0 of N".
- `web/app/components/FindingRow.tsx` (new) — the reproduction command +
  copy-to-clipboard button + `EvidencePane`, kept out of `_bok-ui.tsx` per
  ruling 4 (a domain concept, not a generic table concern) and passed into
  `FindingsTable` via `renderExpanded`.
- `web/app/scans/[id]/findings/page.tsx` (new) — Screen 3. Client Component
  (like Task 12's live-scan screen, since it owns `ProvenanceRail`
  open/close state), `params`/`searchParams` unwrapped with `use()`.
  `?fixture=` replays `./fixtures.ts`; absent a fixture it calls the real
  `getFindings`/`getScan` (untested by this task's RED suite, per ruling 5).
- `web/app/scans/[id]/findings/fixtures.ts` (new) — the four fixtures
  (`mismatch`, `unknown-revision`, `mixed`, `clean`), grounded in real
  check ids, real CWE-shaped strings, and real taxonomy refs pulled from
  `agent_perimeter/checks/taxonomy.yaml` (`owasp-llm:LLM01/LLM06`,
  `owasp-mcp:MCP01/MCP07/MCP10`, `mcp-spec:2026-07-28-changelog`).
- `web/src/lib/api.ts` (modified) — narrowed `getFindings`'s return type from
  `unknown[]` to a new exported `Finding` interface (plus `FindingClaim`,
  `FindingEvidence`, `FindingLocation`) matching the real wire shape
  (`agent_perimeter/model/finding.py`, `_contracts.py::Claim`) field-for-field.
- `web/app/globals.css` (modified) — `.bok-row-expandable` (cursor + hover),
  `.bok-conformance-strip`, `.bok-finding-expanded`, `.bok-finding-reproduction`.

## Judgment calls made (flagging for review)

1. **`ProvenanceChainEntry.source` has no wire equivalent.** The real `Claim`
   model (confirmed directly against `_contracts.py`) carries no `source`
   field, but `_bok-ui.tsx`'s `ProvenanceRail` requires one per chain entry.
   `page.tsx::claimSource()` synthesizes it from the finding's own
   `location` (`uri:line`) when present, falling back to `check_id` — the
   closest real anchor available, not an invented file path. Every entry in
   a finding's claim chain (the claim itself plus its `parents`, recursively)
   uses the same finding-level source label, since nested claims carry no
   location of their own either.
2. **`claim.derivation` is optional on the wire** (`Claim.derivation:
   Derivation | None`); `toRow()` defaults absent derivation to `"artifact"`
   (the most generic value) rather than fabricating a more specific one.
3. **Evidence-kind vocabulary mismatch.** Backend `Evidence.kind` is
   transcript/excerpt/screenshot/diff; `EvidencePane`'s `kind` prop is
   code/dom/document (pre-existing, unrelated enum). `mapEvidenceKind()`
   maps excerpt/diff → code, transcript → document, screenshot → dom (no
   real image-rendering equivalent exists yet) — flagged with a ponytail
   comment as the upgrade path if a screenshot finding ever needs more than
   a text placeholder.
4. **`page.tsx` as a Client Component using `use()`**, not an `await`-based
   async Server Component like the older `/findings` route. The dispatch's
   ruling 8 named both `scans/[id]/page.tsx` (which actually uses `use()`,
   not `await`) and `findings/page.tsx`'s `await searchParams` pattern as
   precedent; since this screen needs to own `ProvenanceRail`
   open/close state and row-expansion interactivity, only the Client
   Component + `use()` pattern (Task 12's actual code, not just its prose
   description) fits without adding an extra wrapper file.

## TDD evidence

**RED** (`npx playwright test tests/findings.spec.ts`, before any
implementation file existed): 7 of 8 failed with 404s against the
not-yet-created route; the 8th ("every finding row shows its CWE...") passed
vacuously — its `for` loop over `page.getByTestId("finding-row").all()`
found zero rows on the 404 page, so the loop body never ran. Confirmed this
was the expected RED-phase shape before writing any GREEN code.

**GREEN**, run twice for reliability:
```
Running 8 tests using 8 workers
  ok 1..8  (all tests/findings.spec.ts tests)
8 passed (20.9s)
...
8 passed (14.6s)
```

**Full-suite regression check** (step 3 — `_bok-ui.tsx` is shared with Tasks
10–12), run twice:
```
Running 22 tests using 11 workers
  ok  1..22  (findings.spec.ts × 8, live-scan.spec.ts × 5,
              scan-setup.spec.ts × 5, tokens.spec.ts × 3,
              provenance-rail.spec.ts × 1)
22 passed (19.3s)
...
22 passed (17.4s)
```
No regressions in Tasks 10–12's existing tests.

**Additional verification:**
- `npx tsc --noEmit` — clean, no output (`noUncheckedIndexedAccess` and
  `strict` both on).
- `npx eslint` on all touched/new files — clean, no output.
- `npx next build` — clean production build, all 5 routes compiled
  (`/`, `/findings`, `/scans/[id]`, `/scans/[id]/findings`, `/_not-found`).

## Self-review findings

- Verified the CSV case-sensitivity gotcha (ruling 2) directly rather than
  assuming it — it was real; fixed by decoupling `CSV_COLUMNS` from
  `FINDINGS_COLUMNS` rather than lowercasing the on-screen `<th>` text.
- Verified the shared-component risk (ruling 4's regression concern)
  concretely: the interactive `<Claim>` wrap around the title cell is
  strictly gated behind `onClaimActivate` being supplied. Without that
  gate, every `FindingsTable` row — including the pre-existing `/findings`
  fixture route's 5 rows — would render a `data-testid="claim"` element,
  which would break `provenance-rail.spec.ts`'s `page.getByTestId("claim")`
  (no `.first()`) with a strict-mode multi-match violation. Confirmed via
  the full-suite run that this didn't happen.
- All new `<td>`/row-click affordances degrade to the pre-existing behaviour
  when `onClaimActivate`/`renderExpanded` are omitted (old route unaffected).
- No secrets, no live-service validation, no active probing introduced —
  this is a pure rendering task against fixture/typed-API data.

## Issues / concerns

- None blocking. The two judgment calls above (`source` synthesis,
  evidence-kind mapping) are reasonable but not spec-mandated; flagging for
  awareness in case a future task defines a real backend `source` field or
  a richer evidence-kind vocabulary.
- Did not add a dedicated axe accessibility test for this screen (not one
  of the 8 RED tests, and out of this task's explicit scope) — the broader
  project testing bar (axe zero serious/critical) presumably gets covered
  by a later, dedicated a11y pass across all screens.

---

## Fix report: review round 1 (2 Important findings)

### Important #1 — keyboard double-activation on `Claim` inside an expandable row

**Root cause.** `Claim`'s `handleKeyDown` (`web/src/lib/_bok-ui.tsx`)
activated on `Enter`/`Space`/`Meta+.`/`Ctrl+.` but never called
`stopPropagation()`. `FindingsTable`'s `onCellKeyDown` separately reacts to
`Enter`/`Space` on any focused cell to toggle row expansion (added this
task, for keyboard parity with the mouse row-click toggle). Since the
`Claim` lives inside a `<td>` with that handler, pressing `Enter` on a
focused `Claim` bubbled from the `<span role="button">` up to the `<td>`,
firing both handlers: the rail opened *and* the row expanded underneath it.

**Fix, and why this rung of the ladder.** Traced every `Claim` caller first
(`web/app/findings/ProvenanceDemo.tsx` — a bare `<p>`, no ancestor
keydown handler; `_bok-ui.tsx`'s own `FindingsTable` title cell — the one
with the conflict). Fixed at the shared `Claim` component
(`event.stopPropagation()` right after `event.preventDefault()`, only on
the branch that actually activates) rather than adding a "does this cell
contain a Claim" check to `onCellKeyDown` — one guard in the component that
owns the keys, not a check duplicated into every current and future
container that nests a `Claim` inside its own keyboard handling. Verified
safe for the other caller: `ProvenanceDemo` has no parent keydown listener
to stop, so nothing there depended on the bubble.

**Regression test**, appended to `web/tests/findings.spec.ts`:
```ts
test("Enter on a claim inside an expandable row only opens the rail, not the row underneath it", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
  await expect(page.getByTestId("reproduction")).toHaveCount(0);
});
```
Verified this test is a real regression check, not a tautology: temporarily
reverted `stopPropagation()` to a no-op comment and re-ran just this test —
it failed exactly as the reviewer predicted (`getByTestId("reproduction")`
resolved to 1 element instead of 0, i.e. the row had expanded). Restored the
fix and re-ran; passes.

### Important #2 — the "mismatch" fixture didn't match what `revision.conformance_mismatch.py` actually emits

**Root cause.** The fixture was written from the brief's illustrative copy,
not from the real check. Read `agent_perimeter/checks/revision/
conformance_mismatch.py` and `agent_perimeter/transport/revision.py`
directly (as the reviewer did) and confirmed all four specific gaps:
- Real `cwe` is always `"CWE-440"`; real `taxonomy_refs` is always the pair
  `("owasp-mcp:MCP10", "mcp-spec:2026-07-28-changelog")` together, never
  split or reordered.
- Real `evidence.kind` is always `EXCERPT` (wire value `"excerpt"`), never
  `"transcript"`.
- Real severity comes from `SECURITY_CONSEQUENCE`, keyed only on
  `RESULT_TYPE`/`SERVER_DISCOVER` (MEDIUM) and `CACHEABLE_RESULT` (LOW) —
  never HIGH, and every other feature is INFO, not MEDIUM.
- The check diffs `BUNDLES[claimed] & PASSIVELY_OBSERVABLE_FEATURES` against
  the fingerprint's observed features. `PASSIVELY_OBSERVABLE_FEATURES`
  (`transport/revision.py`) deliberately excludes `MRTR` and
  `SUBSCRIPTIONS_LISTEN` — the module docstring states outright that a
  passive fingerprint can never grant either — so this check can
  structurally never name `subscriptions_listen` as a missing feature. My
  original fixture's headline finding did exactly that.

**Fix.** Rebuilt `MISMATCH_FINDINGS`'s two `revision.conformance_mismatch`
entries (`web/app/scans/[id]/findings/fixtures.ts`) to mirror the real
check's `run()` field-for-field: title format
`"Server claims {revision} but does not implement {feature}: {consequence}"`,
real `cwe`/`taxonomy_refs` pair, `evidence.kind: "excerpt"` with the real
`"claimed: …\nmissing: …\nobserved: …"` excerpt format, `claim.confidence:
null` (the real `Claim` construction never sets one here), and features
drawn from the real eligible set (`{server_discover, result_type,
cacheable_result, param_headers, extensions}` — the bundle intersected with
`PASSIVELY_OBSERVABLE_FEATURES`). Chose `cacheable_result` (LOW) and
`result_type` (MEDIUM) as the two missing features so the fixture exercises
both real non-INFO severities rather than degenerating to INFO-only.

Went one step further than the review's literal ask, at zero extra file
cost since I was already rebuilding this exact object: also corrected
`scan.featuresObserved` for the `mismatch` fixture to drop `mrtr` and
`subscriptions_listen` (previously listed as "observed", which the real
passive fingerprinter can never do — same root fact the review surfaced,
applied consistently to the sibling field in the same fixture object I was
already touching). `featuresObserved` for `mixed`/`clean` left untouched —
those weren't flagged, and generalizing the fix to every fixture is a
separate, broader cleanup the review didn't ask for.

**Not touched:** the four Minor findings (deferred, per the review, to the
whole-branch triage ledger) and the `static.token_passthrough` fixture
entry (a different check id, not part of either Important finding).

### Re-verification

- `npx tsc --noEmit` — clean.
- `npx eslint` on all touched files — clean.
- `npx playwright test tests/findings.spec.ts` (now 9 tests) — 9/9 passed,
  run twice for reliability.
- `npx playwright test` (full suite, 23 tests — one more than before, the
  new regression test) — 23/23 passed once, given this round only touched
  `_bok-ui.tsx`, a fixture-data file, and the test file (no other component
  changed), one full-suite pass plus the two `findings.spec.ts`-only passes
  above was judged sufficient re-verification depth for this round.

### Files changed this round

- `web/src/lib/_bok-ui.tsx` — `Claim.handleKeyDown` now calls
  `stopPropagation()` on activation.
- `web/app/scans/[id]/findings/fixtures.ts` — `mismatch` fixture's two
  `revision.conformance_mismatch` findings rebuilt to match the real check;
  `mismatch.scan.featuresObserved` corrected to exclude structurally
  unobservable features.
- `web/tests/findings.spec.ts` — one new regression test.
