import { expect, test } from "@playwright/test";

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
