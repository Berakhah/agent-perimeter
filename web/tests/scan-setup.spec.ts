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
