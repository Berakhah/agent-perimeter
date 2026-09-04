import { expect, test } from "@playwright/test";

test("a policy-flagged node pulses once and then holds a ring", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "playing");
  await expect(node).toHaveAttribute("data-pulse", "done", { timeout: 3_000 });
  await expect(node).toHaveAttribute("data-ring", "true");
});

test("reduced motion skips the pulse and keeps the ring", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "skipped");
  await expect(node).toHaveAttribute("data-ring", "true");
});

test("every edge exposes its derivation", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  for (const edge of await page.getByTestId("edge").all()) {
    await expect(edge).toHaveAttribute("data-derivation", /schema|description|probe|artifact/);
  }
});

test("a probe-derived edge is visually distinct from a description-derived one", async ({
  page,
}) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const probe = page.locator("[data-derivation='probe']").first();
  const desc = page.locator("[data-derivation='description']").first();
  expect(await probe.getAttribute("stroke-dasharray")).not.toBe(
    await desc.getAttribute("stroke-dasharray"),
  );
});

test("the graph is fully navigable from the keyboard", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  await page.keyboard.press("Tab");
  await expect(page.getByTestId("node").first()).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("a text alternative lists every node and edge", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const table = page.getByRole("table", { name: /capability edges/i });
  await expect(table).toBeVisible();
  await expect(table.getByRole("row")).toHaveCount(await page.getByTestId("edge").count() + 1);
});

test("an empty graph explains itself", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=no-tools");
  await expect(page.getByTestId("empty-state")).toContainText(/no tools were enumerated/i);
});
