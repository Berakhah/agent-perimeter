### Task 12: Screen 2 — live scan

**Files:**
- Create: `web/app/scans/[id]/page.tsx`
- Create: `web/app/components/PhaseGroup.tsx`
- Test: `web/tests/live-scan.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/events` (SSE), `Skeleton`, `RunTimeline`, `QuotaStrip`.

Brief §7 screen 2. **Skeletons, never spinners** (`00` §5.5). `QuotaStrip` appears only if a model lane engages — which, given the determinism budget, is the exception rather than the rule, and the screen should make that visible rather than hide it.

- [ ] **Step 1: RED**

```ts
test("checks stream in grouped by phase", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.getByRole("group", { name: /revision/i })).toBeVisible();
  await expect(page.getByTestId("check-row")).toHaveCount(29, { timeout: 10_000 });
});

test("no spinner is ever rendered", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.locator("[data-loading='spinner']")).toHaveCount(0);
  await expect(page.getByTestId("skeleton").first()).toBeVisible();
});

test("skipped checks are shown with a reason, not omitted", async ({ page }) => {
  await page.goto("/scans/1?fixture=degraded");
  const skipped = page.getByTestId("check-row").filter({ hasText: /skipped/i });
  await expect(skipped).toHaveCount(1);
  await expect(skipped).toContainText(/no model provider/i);
});

test("the quota strip is absent when no model lane engages", async ({ page }) => {
  await page.goto("/scans/1?fixture=deterministic");
  await expect(page.getByTestId("quota-strip")).toHaveCount(0);
});

test("progress is announced to assistive technology", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.getByRole("status")).toContainText(/\d+ of 29/);
});
```

- [ ] **Step 2: GREEN**

`EventSource` against the SSE endpoint, checks grouped by phase, skeleton rows for pending checks, an `aria-live="polite"` status region reporting `n of 29`, and a terminal summary reading *"No findings for the checks that ran"* plus the skipped count when the run is clean — never *"You're secure!"*.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/live-scan.spec.ts
git add web/app/scans web/tests/live-scan.spec.ts
git commit -m "feat: live scan screen with skeletons and visible skipped checks"
```

---

