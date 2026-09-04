import { expect, test } from "@playwright/test";

test("with a single scan the screen explains what it needs", async ({ page }) => {
  await page.goto("/scans/1/drift?fixture=single-scan");
  await expect(page.getByTestId("empty-state")).toContainText(
    /needs at least two scans of the same target/i,
  );
  await expect(page.getByTestId("empty-state")).not.toContainText(/coming soon/i);
});

test("with two scans the description diff renders word-level", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const diff = page.getByTestId("diff-view");
  // Post-review correctness fix: these two lines were "read the config
  // file" / "read any file" (the brief's suggested wording, whole clause).
  // A real word-level diff (`diffWords`, LCS-based) correctly leaves "read"
  // and "file" as plain unchanged text on both sides -- they're genuinely
  // the same words in the same relative order in both descriptions -- and
  // marks only the words that actually changed. Asserting the old, wider
  // substrings would require reintroducing the exact "everything after the
  // first difference is changed" bug this fix removes (proved out
  // empirically against the `diff` package before making this edit: no
  // fixture wording containing literal "read"/"file" on both sides can
  // make a correct diff mark them as changed -- that's what "correct"
  // means here). This narrower assertion is what the fixed algorithm
  // honestly produces for this fixture, and still proves the same thing
  // the original line intended: the diff is real and word-level, not a
  // whole-line replacement.
  await expect(diff.getByTestId("removed")).toContainText("the config");
  await expect(diff.getByTestId("added")).toContainText("any");
});

test("added and removed carry a glyph, not just colour", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  await expect(page.getByTestId("added").first()).toHaveAttribute("data-glyph", "+");
  await expect(page.getByTestId("removed").first()).toHaveAttribute("data-glyph", "−");
});

test("the timeline is ordered oldest to newest with absolute dates", async ({ page }) => {
  await page.goto("/scans/2/drift?fixture=changed-description");
  const stamps = await page.getByTestId("drift-timestamp").allInnerTexts();
  expect(stamps).toEqual([...stamps].sort());
  expect(stamps[0]).toMatch(/\d{4}-\d{2}-\d{2}/);
});
