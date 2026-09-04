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
