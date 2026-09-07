import { expect, test } from "@playwright/test";

// Covers task-10 review Finding 3: a closed ProvenanceRail must have zero
// reachable/tabbable descendants (the `inert` DOM property, not just the
// slide-out transform), and focus must move into the rail on open and back
// to the trigger on close.
test("a closed provenance rail has no reachable descendants, and focus moves correctly", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");

  const rail = page.getByTestId("provenance-rail");
  // The real screen's `mixed` fixture carries several claim-activatable rows
  // (the fixture-demo page this test used to target rendered exactly one,
  // standalone `Claim`) -- `.first()` matches `findings.spec.ts`'s own
  // disambiguation for the same testid on this route.
  const trigger = page.getByTestId("claim").first();
  const closeButton = page.getByRole("button", { name: "Close provenance rail" });

  // Closed: inert, and its close button is not part of the tab order.
  await expect(rail).toHaveJSProperty("inert", true);

  await trigger.click();

  // Open: no longer inert, focus moved to the close button inside it.
  await expect(rail).toHaveJSProperty("inert", false);
  await expect(closeButton).toBeFocused();

  await page.keyboard.press("Escape");

  // Closed again: inert restored, focus returned to the element that opened it.
  await expect(rail).toHaveJSProperty("inert", true);
  await expect(trigger).toBeFocused();
});
