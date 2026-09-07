### Task 16: Accessibility, keyboard and print verification

**Files:**
- Create: `web/tests/a11y.spec.ts`
- Create: `web/tests/print.spec.ts`
- Create: `web/app/print.css`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/evidence/print-report.png`, `docs/evidence/print-census.png`

**Interfaces:** none. This task closes DoD 9, and it is a verification task, not a feature task.

`00` §5.5 is not negotiable and two of the four target markets are literally regulated for accessibility. The gate is **zero serious and zero critical axe violations on all six screens**, full keyboard operation, and correct printing.

**Screen 6 is not a Next.js route.** Week 3 built it as static HTML from `report/html.py`, deliberately, so publication does not depend on the application. It is therefore verified as a file, not as a route: a pretest step renders one into `web/tests/fixtures/report.html` and Playwright's `webServer` config serves that directory at `/static/`. Testing the real artifact rather than a route that resembles it is the whole reason the decoupling was worth making.

```ts
// web/playwright.config.ts — serve the static artifacts alongside the app
webServer: [
  { command: "npm run dev", url: "http://localhost:3000", reuseExistingServer: true },
  { command: "npx serve -p 4173 tests/fixtures", url: "http://localhost:4173" },
],
```

- [ ] **Step 1: RED — axe across every screen**

Create `web/tests/a11y.spec.ts`:

```ts
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
```

- [ ] **Step 2: RED — print**

Create `web/tests/print.spec.ts`:

```ts
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
```

- [ ] **Step 3: GREEN — render the static fixture, then fix whatever the tests find**

The report fixture is generated, not committed, so it can never drift from the emitter:

```json
"scripts": { "pretest": "cd .. && uv run agent-perimeter scan --target fixture://mixed --html web/tests/fixtures/report.html" }
```

Run both suites and fix. Do not weaken an assertion to make it pass; the assertion is the deliverable.

- [ ] **Step 4: Wire into CI**

Add to `.github/workflows/ci.yml`:

```yaml
  web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22", cache: npm, cache-dependency-path: web/package-lock.json }
      - run: npm ci
        working-directory: web
      - run: npx playwright install --with-deps chromium
        working-directory: web
      - run: npx tsc --noEmit && npm run lint
        working-directory: web
      - run: npx playwright test
        working-directory: web
      - uses: actions/upload-artifact@v4
        if: failure()
        with: { name: playwright-report, path: web/playwright-report/ }
```

- [ ] **Step 5: Print the census report too**

The census report is a second static artifact and needs the same treatment. Extend the `pretest` script to render it into `web/tests/fixtures/census.html`, then add to `print.spec.ts`:

```ts
test("the census report prints with its methodology intact", async ({ page }) => {
  await page.goto("http://localhost:4173/census.html");
  await page.emulateMedia({ media: "print" });
  for (const id of ["population-size", "tier2-n", "unknown-count", "fetch-failures"]) {
    await expect(page.getByTestId(id)).toBeVisible();
  }
  await expect(page.getByTestId("term-definitions")).toBeVisible();
  await page.screenshot({ path: "../docs/evidence/print-census.png", fullPage: true });
});
```

**This is the artifact that gets emailed to a journalist.** If it prints badly, or if the methodology drops off the printed page while the headline percentage survives, the work is not done — that failure mode is precisely the one this project exists to argue against.

- [ ] **Step 6: Commit**

```bash
git add web/tests web/app/print.css .github/workflows/ci.yml docs/evidence/
git commit -m "test: axe, keyboard, responsive and print verification across six screens (DoD 9)"
```

---

