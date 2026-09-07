### Task 14: Screen 4 — the capability graph

**Files:**
- Create: `web/app/scans/[id]/graph/page.tsx`
- Create: `web/app/components/CapabilityGraph.tsx`
- Create: `web/app/components/EdgeTooltip.tsx`
- Test: `web/tests/graph.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/graph`, `Claim`, `ProvenanceRail`.

Brief §7 screen 4, the signature moment, and the screen the deck leads with. Three requirements are load-bearing:

- Any node satisfying a policy predicate **pulses once, amber, on first render**, then holds a static ring. One orchestrated moment — not scattered effects, and not a loop.
- Hovering or focusing an edge shows **why** the capability was inferred: schema, description, or probe. B9 again — an edge inferred from prose and an edge confirmed by a probe are not the same claim and must not look the same.
- Under `prefers-reduced-motion` the pulse does not run and the ring is present from the first frame. The information must not live in the animation.

A force-directed graph is also the easiest screen in the product to make unusable with a keyboard, so the accessible path is built first and the canvas second.

- [ ] **Step 1: RED**

```ts
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
```

- [ ] **Step 2: GREEN — accessible table first, canvas second**

Render the edge table (always in the DOM, visually secondary), then the force-directed graph over the same data. Focus moves through nodes in the table's order, so keyboard and visual navigation cannot diverge. Derivation maps to stroke pattern **and** a legend entry — never colour alone.

- [ ] **Step 3: REFACTOR — the pulse belongs to render, not to a timer**

```ts
// ponytail: pulse is a one-shot CSS animation keyed on first paint, not a JS timer.
// A timer would re-fire on re-render and turn the one orchestrated moment into a
// nervous tic, which is the exact failure 00 §5.3 warns about.
```

- [ ] **Step 4: Commit**

```bash
npx playwright test tests/graph.spec.ts
git add web/app web/tests/graph.spec.ts
git commit -m "feat: capability graph with per-edge derivation and a single pulse"
```

---

