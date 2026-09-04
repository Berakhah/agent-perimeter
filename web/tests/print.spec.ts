import { expect, test } from "@playwright/test";

test("the report prints without interactive chrome", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  await expect(page.getByTestId("nav")).toBeHidden();
  await expect(page.getByRole("button", { name: /export/i })).toBeHidden();
  await expect(page.getByTestId("methodology-footer")).toBeVisible();
  await page.screenshot({ path: "../docs/evidence/print-report.png", fullPage: true });
});

test("severity survives greyscale", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  for (const badge of await page.getByTestId("severity-badge").all()) {
    await expect(badge).toHaveAttribute("data-glyph", /.+/);
  }
});

test("no finding row is split across a page break", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  const broken = await page.evaluate(() =>
    [...document.querySelectorAll("[data-testid='finding-row']")].filter(
      (el) => getComputedStyle(el).breakInside !== "avoid",
    ).length,
  );
  expect(broken).toBe(0);
});

test("the census report prints with its methodology intact", async ({ page }) => {
  await page.goto("http://localhost:4173/census.html");
  await page.emulateMedia({ media: "print" });
  for (const id of ["population-size", "tier2-n", "unknown-count", "fetch-failures"]) {
    await expect(page.getByTestId(id)).toBeVisible();
  }
  await expect(page.getByTestId("term-definitions")).toBeVisible();
  await page.screenshot({ path: "../docs/evidence/print-census.png", fullPage: true });
});
