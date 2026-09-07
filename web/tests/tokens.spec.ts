import { expect, test } from "@playwright/test";

test("severity is never encoded in colour alone", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  for (const row of await page.getByRole("row").all()) {
    const badge = row.getByTestId("severity-badge");
    if (await badge.count()) {
      await expect(badge).toHaveAttribute("data-glyph", /.+/);
      await expect(badge).not.toHaveText("");
    }
  }
});

test("numbers are tabular", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const cell = page.getByTestId("numeric-cell").first();
  await expect(cell).toHaveCSS("font-variant-numeric", /tabular-nums/);
});

test("no external host is contacted", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    const url = new URL(r.url());
    if (!["localhost", "127.0.0.1"].includes(url.hostname)) external.push(r.url());
  });
  await page.goto("/");
  expect(external).toEqual([]);
});
