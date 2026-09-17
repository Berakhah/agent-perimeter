import { expect, test } from "@playwright/test";

test("active mode is locked until a scope file is attached", async ({ page }) => {
  await page.goto("/");
  const active = page.getByRole("radio", { name: /active/i });
  await expect(active).toBeDisabled();
  await expect(page.getByTestId("active-lock-reason")).toHaveText(
    /scope file.*authorisation/i,
  );
});

test("the lock reason is one sentence and does not apologise", async ({ page }) => {
  await page.goto("/");
  const text = await page.getByTestId("active-lock-reason").innerText();
  expect(text.split(".").filter(Boolean).length).toBe(1);
  expect(text.toLowerCase()).not.toMatch(/sorry|unfortunately|apolog/);
});

test("attaching a valid scope file unlocks active mode", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-valid.json");
  await expect(page.getByRole("radio", { name: /active/i })).toBeEnabled();
});

test("an incomplete scope file names the missing field", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-no-attestation.json");
  // Next.js App Router mounts its own always-present role="alert" live
  // region for route-change announcements (a real accessibility feature,
  // node_modules/next/dist/client/components/app-router-announcer.js --
  // not application code, unconditional on every page, no config opt-out).
  // .filter() picks out our error surface without touching that unrelated
  // framework node or reducing its own accessibility function.
  const alert = page.getByRole("alert").filter({ hasText: "attestation" });
  await expect(alert).toContainText("attestation");
  await expect(page.getByRole("radio", { name: /active/i })).toBeDisabled();
});

test("the whole form is operable from the keyboard", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByLabel(/target/i)).toBeFocused();
});

// Web UI redesign (spec §4.1). Each test asserts an end state -- an
// attribute or a computed style -- not a transition's intermediate frames.
test("the dropzone marks itself while a file is dragged over it", async ({ page }) => {
  await page.goto("/");
  const zone = page.locator(".bok-scope-file-field");
  await expect(zone).toHaveAttribute("data-dragging", "false");
  await zone.dispatchEvent("dragenter");
  await expect(zone).toHaveAttribute("data-dragging", "true");
  await zone.dispatchEvent("dragleave");
  await expect(zone).toHaveAttribute("data-dragging", "false");
});

test("the mode selector records the lock state for its transition", async ({ page }) => {
  await page.goto("/");
  const selector = page.locator(".bok-mode-selector");
  await expect(selector).toHaveAttribute("data-unlocked", "false");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-valid.json");
  await expect(selector).toHaveAttribute("data-unlocked", "true");
});

test("the submit button reads disabled until a target is typed", async ({ page }) => {
  await page.goto("/");
  const submit = page.getByRole("button", { name: /start scan/i });
  await expect(submit).toBeDisabled();
  await expect(submit).toHaveCSS("cursor", "not-allowed");
  await page.getByLabel(/target/i).fill("https://example.test/mcp");
  await expect(submit).toBeEnabled();
  await expect(submit).toHaveCSS("cursor", "pointer");
});

test("the submit button shows its submitting state while the request is in flight", async ({ page }) => {
  // Hold the API response open so the in-flight state is observable.
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  await page.route("**/api/scans", async (route) => {
    await held;
    await route.fulfill({ status: 202, contentType: "application/json", body: JSON.stringify({ id: "9" }) });
  });
  await page.goto("/");
  await page.getByLabel(/target/i).fill("https://example.test/mcp");
  const submit = page.getByRole("button", { name: /start/i });
  await submit.click();
  await expect(submit).toHaveAttribute("data-submitting", "true");
  release();
  await page.waitForURL(/\/scans\/9/);
});

test("reduced motion leaves every scan-setup end state intact", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/");
  await page.getByTestId("scope-file").setInputFiles("tests/fixtures/scope-valid.json");
  await expect(page.locator(".bok-mode-selector")).toHaveAttribute("data-unlocked", "true");
  await expect(page.getByRole("radio", { name: /active/i })).toBeEnabled();
  await page.getByLabel(/target/i).fill("x");
  await expect(page.getByRole("button", { name: /start scan/i })).toHaveCSS("cursor", "pointer");
});
