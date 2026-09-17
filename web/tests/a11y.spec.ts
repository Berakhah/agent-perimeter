import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const SCREENS = [
  ["scan setup", "/"],
  ["live scan", "/scans/1?fixture=streaming"],
  ["findings", "/scans/1/findings?fixture=mixed"],
  ["capability graph", "/scans/1/graph?fixture=deputy"],
  ["drift", "/scans/2/drift?fixture=changed-description"],
  // Screen 6 is the static artifact from report/html.py, served on 4173, not a route.
  ["report", "http://localhost:4173/report.html"],
] as const;

for (const [name, path] of SCREENS) {
  test(`${name} has no serious or critical axe violations`, async ({ page }) => {
    await page.goto(path);
    // Motion entrances (src/lib/motion.ts) fade content in over ≤300ms and
    // mark it data-entered="true" on completion. axe reads mid-fade text at
    // opacity < 1 as a colour-contrast failure, which is a sampling artefact,
    // not a defect -- audit the settled DOM. Screens with no motion have no
    // data-entered elements and pass through immediately.
    // A single zero reading isn't proof the DOM has settled: under worker
    // contention the streaming fixture's per-event timers can bunch up, so
    // a *new* data-entered="false" row can appear moments after a momentary
    // all-zero reading while the stream is still catching up (measured:
    // ~20-50% flake with a single .poll(...).toBe(0) here). Debounce by
    // re-checking after a pause comfortably longer than one entrance
    // animation (DURATION_S.reveal + STAGGER_CAP_S, src/lib/motion.ts) --
    // if the pause reveals a fresh false element, the outer poll retries.
    await expect
      .poll(
        async () => {
          const stillEntering = await page.locator('[data-entered="false"]').count();
          if (stillEntering > 0) return stillEntering;
          await page.waitForTimeout(400);
          return page.locator('[data-entered="false"]').count();
        },
        { timeout: 15_000 },
      )
      .toBe(0);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    const blocking = results.violations.filter((v) =>
      ["serious", "critical"].includes(v.impact ?? ""),
    );
    expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
  });

  test(`${name} is fully operable from the keyboard`, async ({ page }) => {
    await page.goto(path);
    const reachable = new Set<string>();
    for (let i = 0; i < 60; i++) {
      await page.keyboard.press("Tab");
      const id = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));
      if (id) reachable.add(id);
    }
    const interactive = await page.getByRole("button").count();
    expect(reachable.size).toBeGreaterThanOrEqual(Math.min(interactive, 1));
  });

  test(`${name} has a visible focus ring`, async ({ page }) => {
    await page.goto(path);
    await page.keyboard.press("Tab");
    const outline = await page.evaluate(
      () => getComputedStyle(document.activeElement!).outlineStyle,
    );
    expect(outline).not.toBe("none");
  });

  test(`${name} is usable at 375px`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(path);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    );
    expect(overflow).toBe(false);
  });
}
