### Task 13: Screen 3 — findings, with the revision conformance strip

**Files:**
- Create: `web/app/scans/[id]/findings/page.tsx`
- Create: `web/app/components/ConformanceStrip.tsx`
- Create: `web/app/components/FindingRow.tsx`
- Test: `web/tests/findings.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/findings`, `FindingsTable`, `EvidencePane`, `SeverityBadge`, `Claim`, `ProvenanceRail`.

Brief §7 screen 3 plus the two deltas from spec §10: a **derivation / feature column** showing which observed features made each check applicable, and the **revision conformance strip** heading the screen — *"claims 2026-07-28 · observes 7 of 10 features · 3 conformance gaps"*. The strip is the differentiator rendered in about four seconds, and it is a header element rather than a new screen.

- [ ] **Step 1: RED**

```ts
test("the conformance strip states claim, observation and gaps", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mismatch");
  const strip = page.getByTestId("conformance-strip");
  await expect(strip).toContainText("claims 2026-07-28");
  await expect(strip).toContainText(/observes \d+ of \d+ features/);
  await expect(strip).toContainText(/\d+ conformance gaps?/);
});

test("a server claiming nothing reads as unknown, not as non-compliant", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=unknown-revision");
  await expect(page.getByTestId("conformance-strip")).toContainText(/revision unknown/i);
});

test("every finding row shows its CWE and a taxonomy reference", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  for (const row of await page.getByTestId("finding-row").all()) {
    await expect(row.getByTestId("cwe")).toHaveText(/CWE-\d+/);
    await expect(row.getByTestId("taxonomy")).not.toHaveText("");
  }
});

test("expanding a row reveals the reproduction command with a copy button", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("finding-row").first().click();
  await expect(page.getByTestId("reproduction")).toBeVisible();
  await expect(page.getByRole("button", { name: /copy/i })).toBeEnabled();
});

test("clicking a claim opens the provenance rail", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().click();
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("the rail also opens from the keyboard", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().focus();
  await page.keyboard.press("Meta+Period");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("csv export carries the provenance column", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: /export csv/i }).click(),
  ]);
  const body = await (await download.createReadStream())!.toArray();
  expect(body.join("")).toContain("provenance");
});

test("empty findings never claim the target is secure", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=clean");
  const empty = page.getByTestId("empty-state");
  await expect(empty).toContainText("No findings for the checks that ran");
  await expect(empty).toContainText(/\d+ skipped/);
  await expect(empty).not.toContainText(/secure/i);
});
```

- [ ] **Step 2: GREEN**

Virtualised `FindingsTable`, severity glyph plus label, filters on severity / check / taxonomy, row expansion into `EvidencePane` with highlight ranges, SARIF / JSON / CSV export, and `ConformanceStrip` reading its three numbers from the scan's `revision_claimed`, observed `FeatureSet` and the `conformance_mismatch` findings.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/findings.spec.ts
git add web/app web/tests/findings.spec.ts
git commit -m "feat: findings screen with the revision conformance strip"
```

---

