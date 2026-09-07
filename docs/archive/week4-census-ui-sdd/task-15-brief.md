### Task 15: Screen 5 — drift stub

**Files:**
- Create: `web/app/scans/[id]/drift/page.tsx`
- Test: `web/tests/drift.spec.ts`

**Interfaces:**
- Consumes: `description_hash` and `drift_event` (already in the v1 schema per the brief), `DiffView`, `EmptyState`.

Brief §7 screen 5 is a v2 surface stubbed in v1. Stubbed means **honest about being a stub** — it renders real data when two scans of the same target exist, and an empty state naming what it needs when they do not. It does not render fake data, and it does not promise a subscription that has not been built.

A silently-changed tool description rendered as a word-level red-lined diff is the most visceral artifact in the product, so the diff itself is real even though the monitoring around it is not.

- [ ] **Step 1: RED**

```ts
test("with a single scan the screen explains what it needs", async ({ page }) => {
  await page.goto("/scans/1/drift?fixture=single-scan");
  await expect(page.getByTestId("empty-state")).toContainText(
    /needs at least two scans of the same target/i,
  );
  await expect(page.getByTestId("empty-state")).not.toContainText(/coming soon/i);
});

test("with two scans the description diff renders word-level", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const diff = page.getByTestId("diff-view");
  await expect(diff.getByTestId("removed")).toContainText("read the config file");
  await expect(diff.getByTestId("added")).toContainText("read any file");
});

test("added and removed carry a glyph, not just colour", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  await expect(page.getByTestId("added").first()).toHaveAttribute("data-glyph", "+");
  await expect(page.getByTestId("removed").first()).toHaveAttribute("data-glyph", "−");
});

test("the timeline is ordered oldest to newest with absolute dates", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const stamps = await page.getByTestId("drift-timestamp").allInnerTexts();
  expect(stamps).toEqual([...stamps].sort());
  expect(stamps[0]).toMatch(/\d{4}-\d{2}-\d{2}/);
});
```

- [ ] **Step 2: GREEN**

`RunTimeline` of scans for the target, `DiffView` on `description_hash` mismatches, absolute ISO dates (never "3 days ago" — this is an audit artifact), and an empty state that states the precondition.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/drift.spec.ts
git add web/app web/tests/drift.spec.ts
git commit -m "feat: drift screen rendering real diffs, honest about being a v1 stub"
```

---

