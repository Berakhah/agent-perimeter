import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Playwright's webServer drives the dev server from 127.0.0.1 while pages
  // fetch their own /_next/* assets from the same origin under a different
  // hostname spelling -- silences the resulting dev-only cross-origin
  // warning so `npx playwright test` output stays pristine.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
};

export default nextConfig;
