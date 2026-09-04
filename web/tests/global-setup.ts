import { execSync } from "node:child_process";

/**
 * `npm run pretest` (package.json) only fires automatically ahead of
 * `npm test` -- npm's lifecycle hooks don't fire for `npx playwright test`,
 * which is exactly how this project's CI (`.github/workflows/ci.yml`) and
 * every local run invoke this suite. A Playwright `globalSetup` runs before
 * every invocation regardless of how the test command was spelled, so this
 * is the one thing that actually guarantees `web/tests/fixtures/report.html`
 * and `census.html` exist before the first test touches port 4173.
 */
export default function globalSetup(): void {
  execSync("npm run pretest", { stdio: "inherit" });
}
