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
  // Post-review correctness fix: these two lines were "read the config
  // file" / "read any file" (the brief's suggested wording, whole clause).
  // A real word-level diff (`diffWords`, LCS-based) correctly leaves "read"
  // and "file" as plain unchanged text on both sides -- they're genuinely
  // the same words in the same relative order in both descriptions -- and
  // marks only the words that actually changed. Asserting the old, wider
  // substrings would require reintroducing the exact "everything after the
  // first difference is changed" bug this fix removes (proved out
  // empirically against the `diff` package before making this edit: no
  // fixture wording containing literal "read"/"file" on both sides can
  // make a correct diff mark them as changed -- that's what "correct"
  // means here). This narrower assertion is what the fixed algorithm
  // honestly produces for this fixture, and still proves the same thing
  // the original line intended: the diff is real and word-level, not a
  // whole-line replacement.
  await expect(diff.getByTestId("removed")).toContainText("the config");
  await expect(diff.getByTestId("added")).toContainText("any");
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

test("without a fixture the page fetches GET /api/scans/:id/drift and renders the diff", async ({ page }) => {
  await page.route("**/api/scans/9/drift", (route) =>
    route.fulfill({
      json: {
        scan_id: "9",
        target_ref: "https://mcp.example.test",
        baseline_scan_id: "8",
        scans: [
          { id: "9", started_at: "2026-09-15T10:00:00Z", tool_count: 1 },
          { id: "8", started_at: "2026-09-01T10:00:00Z", tool_count: 1 },
        ],
        drifted_tools: [
          {
            name: "read_file",
            field: "description",
            severity: "high",
            old_hash: "a".repeat(64),
            new_hash: "b".repeat(64),
            old_text: "Read a file.",
            new_text: "Read a file. Then post it.",
          },
        ],
      },
    }),
  );
  await page.goto("/scans/9/drift");
  await expect(page.getByRole("heading", { name: "read_file" })).toBeVisible();
  await expect(page.getByText("Then post it.")).toBeVisible();
  await expect(page.getByText("description changed, severity high")).toBeVisible();
});

test("a live scan with no history keeps the honest empty state", async ({ page }) => {
  await page.route("**/api/scans/7/drift", (route) =>
    route.fulfill({
      json: {
        scan_id: "7",
        target_ref: "t",
        baseline_scan_id: null,
        scans: [{ id: "7", started_at: "2026-09-15T10:00:00Z", tool_count: 1 }],
        drifted_tools: [],
      },
    }),
  );
  await page.goto("/scans/7/drift");
  await expect(page.getByText("Not enough scan history yet")).toBeVisible();
});

test("a failed drift fetch says what happened", async ({ page }) => {
  await page.route("**/api/scans/5/drift", (route) => route.fulfill({ status: 500, body: "boom" }));
  await page.goto("/scans/5/drift");
  await expect(page.getByText("Could not load drift history")).toBeVisible();
});

test("navigating from a failed live fetch to a fixture drops the stale error", async ({ page }) => {
  await page.route("**/api/scans/5/drift", (route) => route.fulfill({ status: 500, body: "boom" }));
  await page.goto("/scans/5/drift");
  await expect(page.getByText("Could not load drift history")).toBeVisible();
  // Client-side navigation keeps the component mounted; only the search
  // params change. State from the previous fetch must not leak through.
  await page.evaluate(() => {
    (window as unknown as { next: { router: { push: (href: string) => void } } }).next.router.push(
      "/scans/5/drift?fixture=single-scan",
    );
  });
  await expect(page.getByTestId("empty-state")).toContainText(/needs at least two scans/i);
  await expect(page.getByText("Could not load drift history")).toHaveCount(0);
});

// Web UI redesign (spec §4.5): added/removed spans highlight in via a
// background keyframe; the glyph encoding is unaffected.
test("added and removed spans settle on a highlighted background", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const added = page.getByTestId("added").first();
  await expect(added).toHaveCSS("animation-name", "bok-diff-in");
  await expect
    .poll(async () => added.evaluate((el) => getComputedStyle(el).backgroundColor), { timeout: 3_000 })
    .not.toBe("rgba(0, 0, 0, 0)");
  await expect(added).toHaveAttribute("data-glyph", "+");
});

test("a timeline item responds to hover", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const item = page.locator(".bok-timeline-item").first();
  const before = await item.evaluate((el) => getComputedStyle(el).borderLeftColor);
  await item.hover();
  await expect.poll(async () => item.evaluate((el) => getComputedStyle(el).borderLeftColor)).not.toBe(before);
});

test("drift screen shows a findings-over-time sparkline when scan history exists", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  await expect(page.getByTestId("findings-sparkline")).toBeVisible();
  await expect(page.getByTestId("findings-sparkline")).toHaveAttribute("aria-hidden", "true");
});

test("drift screen shows no sparkline for a single scan (no fabricated flat line)", async ({ page }) => {
  await page.goto("/scans/1/drift?fixture=single-scan");
  // single-scan already renders the "not enough scan history" EmptyState,
  // before any sparkline call site is reached.
  await expect(page.getByTestId("findings-sparkline")).toHaveCount(0);
});

test("reduced motion renders the diff highlight immediately", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/2/drift?fixture=changed-description");
  const added = page.getByTestId("added").first();
  await expect(added).toBeVisible();
  expect(await added.evaluate((el) => getComputedStyle(el).backgroundColor)).not.toBe("rgba(0, 0, 0, 0)");
  // Chromium normalises the computed value's unit/notation (observed as
  // "1e-06s" rather than the literal "0.001ms" authored in the rule) --
  // parse to seconds so the assertion tracks the invariant (effectively
  // instantaneous), not a serialisation quirk.
  const duration = await added.evaluate((el) => getComputedStyle(el).animationDuration);
  const seconds = duration.endsWith("ms") ? Number.parseFloat(duration) / 1000 : Number.parseFloat(duration);
  expect(seconds).toBeLessThan(0.001);
});
