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
  use: {
    baseURL: "http://127.0.0.1:3100",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev -- --port 3100",
    url: "http://127.0.0.1:3100",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
