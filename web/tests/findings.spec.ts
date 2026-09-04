import { expect, test } from "@playwright/test";

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

// Review round 1, Important #1: Enter/Space on a Claim nested inside an
// expandable row must not also toggle the row -- RED test 6 above only
// exercises Meta+Period, which the row's own Enter/Space expand-toggle
// handler doesn't intercept, so it never caught this.
test("Enter on a claim inside an expandable row only opens the rail, not the row underneath it", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
  await expect(page.getByTestId("reproduction")).toHaveCount(0);
});
