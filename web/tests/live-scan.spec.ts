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

// Final-review fix wave, Important #2: the real (non-fixture) path used to
// render "No findings for the checks that ran" the instant the terminal SSE
// frame arrived, regardless of the scan's actual findings count. No fixture
// exercises this branch (fixtures never call `getScan`), so the real
// `/api/scans/1/events` and `/api/scans/1` calls are mocked directly --
// this is the first test in this file to touch the non-fixture path at all.
test("a non-zero findings count is never reported as no findings", async ({ page }) => {
  await page.route("**/api/scans/1/events", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: `data: ${JSON.stringify({ terminal: true, completed: 29, total: 29, skipped: [] })}\n\n`,
    }),
  );
  await page.route("**/api/scans/1", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ id: "1", status: "completed", findings_count: 3 }),
    }),
  );

  await page.goto("/scans/1");

  await expect(page.getByTestId("findings-summary")).toContainText("3 findings");
  await expect(page.getByText("No findings for the checks that ran")).toHaveCount(0);
});

test("an unknown findings count reads as unknown, never as a false zero", async ({ page }) => {
  await page.route("**/api/scans/1/events", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/event-stream",
      body: `data: ${JSON.stringify({ terminal: true, completed: 29, total: 29, skipped: [] })}\n\n`,
    }),
  );
  // `findings_count` genuinely absent from the response -- the same shape a
  // scan still in flux, or a backend that hasn't computed it yet, produces.
  await page.route("**/api/scans/1", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ id: "1", status: "completed" }),
    }),
  );

  await page.goto("/scans/1");

  await expect(page.getByTestId("findings-summary")).toContainText(/unknown/i);
  await expect(page.getByText("No findings for the checks that ran")).toHaveCount(0);
});

// Web UI redesign (spec §4.2): each check row enters with a short rise-in.
// The test asserts the *end state* -- `data-entered="true"` is set from
// motion's onAnimationComplete -- never the animation's visual path.
test("check rows reach their entered state after streaming in", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  const first = page.getByTestId("check-row").first();
  await expect(first).toHaveAttribute("data-entered", "false");
  await expect(first).toHaveAttribute("data-entered", "true", { timeout: 3_000 });
  await expect(page.getByTestId("check-row").last()).toHaveAttribute("data-entered", "true", { timeout: 10_000 });
});

// Spec §5/§6: under reduced motion the end state is reached immediately.
// The non-retrying `getAttribute` (not `toHaveAttribute`) is the evidence --
// there is no window in which the row exists but is not yet entered.
test("reduced motion renders check rows already entered", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1?fixture=streaming");
  const first = page.getByTestId("check-row").first();
  await expect(first).toBeVisible();
  expect(await first.getAttribute("data-entered")).toBe("true");
});

// Spec §4.2: the running→terminal swap cross-fades the incoming summary.
// Both role="status" sources must never coexist (page.tsx header comment),
// so only the incoming frame animates -- assert it reaches its end state
// and that the progress announcer is gone by then.
test("the terminal summary fades in and replaces the progress announcer", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  const frame = page.getByTestId("terminal-frame");
  await expect(frame).toHaveAttribute("data-entered", "true", { timeout: 10_000 });
  await expect(page.locator(".bok-scan-progress")).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: /findings/ })).toHaveCount(1);
});

test("reduced motion renders the terminal summary already entered", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1?fixture=streaming");
  const frame = page.getByTestId("terminal-frame");
  await expect(frame).toBeVisible({ timeout: 10_000 });
  expect(await frame.getAttribute("data-entered")).toBe("true");
});
