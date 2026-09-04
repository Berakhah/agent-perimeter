import { defineConfig, devices } from "@playwright/test";

// ponytail: one shared dev-server instance for the whole suite, not a
// production build -- fine for the token/behaviour checks this runs today;
// switch `command` to `npm run build && npm run start` if a future test
// needs production-only behaviour (e.g. minification, real caching headers).
export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  // Renders web/tests/fixtures/report.html + census.html from the real
  // Jinja renderers (analysis/render_web_fixtures.py) before any test runs,
  // regardless of invocation -- `npm run pretest`'s npm lifecycle hook only
  // fires ahead of `npm test`, never ahead of `npx playwright test` (see
  // tests/global-setup.ts).
  globalSetup: "./tests/global-setup.ts",
  use: {
    baseURL: "http://127.0.0.1:3100",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // Task 10's single dev-server entry stays exactly as it was -- every spec
  // file from tokens.spec.ts through drift.spec.ts depends on it. Task 16
  // adds a second entry serving the static report/census artifacts
  // (report/html.py, census_report.py -- screen 6, not a Next.js route) on
  // their own port, alongside it, never instead of it.
  webServer: [
    {
      command: "npm run dev -- --port 3100",
      url: "http://127.0.0.1:3100",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command: "npx serve -p 4173 tests/fixtures",
      url: "http://localhost:4173",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
