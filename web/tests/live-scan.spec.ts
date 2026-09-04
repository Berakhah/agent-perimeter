import { expect, test } from "@playwright/test";

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
  // `Skeleton` (bok-ui) also carries role="status" (`_bok-ui.tsx`) and is
  // legitimately visible from the very first render, before any check has
  // streamed in -- a real, permanent (not merely racy) collision with the
  // progress announcer's own role="status", since Playwright's `toContainText`
  // fails immediately on a strict-mode violation rather than retrying through
  // it (verified directly: both 5-worker and --workers=1 runs failed in
  // under 700ms, not at the 5s timeout). `Skeleton` renders no text at all,
  // so `.filter({ hasText: /of/ })` -- the same disambiguation-by-filter
  // pattern `scan-setup.spec.ts` uses for Next's own route announcer --
  // narrows to the progress announcer without touching either component's
  // real accessibility semantics.
  await expect(page.getByRole("status").filter({ hasText: /of/ })).toContainText(/\d+ of 29/);
});
