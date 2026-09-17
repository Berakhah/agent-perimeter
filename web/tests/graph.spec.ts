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

// Web UI redesign (spec §4.4). End-state assertions; dasharray is checked
// again because it is the derivation encoding and must survive untouched.
test("nodes and edges reach their entered state", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  await expect(page.getByTestId("node").first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  const edges = page.getByTestId("edge");
  await expect(edges.first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(edges.last()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
});

test("the entrance never changes an edge's dash pattern", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const probe = page.locator("[data-derivation='probe']").first();
  const initial = await probe.getAttribute("stroke-dasharray");
  await expect(probe).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  expect(await probe.getAttribute("stroke-dasharray")).toBe(initial);
  expect(await probe.evaluate((el) => getComputedStyle(el).strokeDasharray)).not.toBe("none");
});

test("a flagged node pulses only after it has entered", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "pending");
  await expect(node).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(node).toHaveAttribute("data-pulse", /playing|done/);
  await expect(node).toHaveAttribute("data-pulse", "done", { timeout: 3_000 });
});

test("hovering a tool node marks its edges connected and dims the rest", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const nodes = page.getByTestId("node");
  await expect(nodes.first()).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  const label = await nodes.first().getAttribute("aria-label");
  const toolName = label!.replace(/^Tool /, "").replace(/, policy-flagged$/, "");
  await nodes.first().hover();
  const connected = page.locator(`[data-testid="edge"][data-tool="${toolName}"]`);
  await expect(connected.first()).toHaveAttribute("data-connected", "true");
  const others = page.locator(`[data-testid="edge"]:not([data-tool="${toolName}"])`);
  if (await others.count()) await expect(others.first()).toHaveAttribute("data-dimmed", "true");
  await page.mouse.move(0, 0);
  await expect(connected.first()).toHaveAttribute("data-connected", "false");
});

test("focusing a tool node highlights its edges from the keyboard too", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  await page.keyboard.press("Tab");
  const node = page.getByTestId("node").first();
  await expect(node).toBeFocused();
  const toolName = (await node.getAttribute("aria-label"))!.replace(/^Tool /, "");
  await expect(page.locator(`[data-testid="edge"][data-tool="${toolName}"]`).first()).toHaveAttribute("data-connected", "true");
});

test("reduced motion renders nodes and edges already entered and still pulses nothing", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node").first();
  await expect(node).toBeVisible();
  expect(await node.getAttribute("data-entered")).toBe("true");
  const edge = page.getByTestId("edge").first();
  expect(await edge.getAttribute("data-entered")).toBe("true");
  await expect(page.getByTestId("node-flagged").first()).toHaveAttribute("data-pulse", "skipped");
});
