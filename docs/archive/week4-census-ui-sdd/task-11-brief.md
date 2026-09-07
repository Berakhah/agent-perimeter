### Task 11: Screen 1 — scan setup

**Files:**
- Create: `web/app/page.tsx`
- Create: `web/app/components/ScopeFileField.tsx`
- Create: `web/app/components/ModeSelector.tsx`
- Test: `web/tests/scan-setup.spec.ts`

**Interfaces:**
- Consumes: `POST /api/scans`, `api` client, `EmptyState`, `ErrorState`.

Brief §7 screen 1. The one thing that must be exactly right: **active mode is disabled and visibly locked until a valid scope file is attached, and the lock explains why in one sentence.** The refusal is the selling point, so it has to look deliberate rather than broken.

- [ ] **Step 1: RED**

Create `web/tests/scan-setup.spec.ts`:

```ts
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
  await expect(page.getByRole("alert")).toContainText("attestation");
  await expect(page.getByRole("radio", { name: /active/i })).toBeDisabled();
});

test("the whole form is operable from the keyboard", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByLabel(/target/i)).toBeFocused();
});
```

- [ ] **Step 2: GREEN**

Build the screen: target entry (stdio command / URL / registry ref), `ModeSelector` (passive / active), `ScopeFileField` with drag-drop plus inline attestation entry. Validation calls the API, so the client never decides authorisation on its own — it renders the server's answer.

Lock copy: *"Active checks need a scope file naming the target, the authorising party and a dated attestation."*

- [ ] **Step 3: Screenshot the refusal**

```bash
npx playwright test tests/scan-setup.spec.ts --update-snapshots
```

Commit `web/tests/__screenshots__/active-locked.png` to `docs/evidence/`. Brief §7 asks for it explicitly.

- [ ] **Step 4: Commit**

```bash
git add web/app web/tests/scan-setup.spec.ts docs/evidence/
git commit -m "feat: scan setup screen with active mode locked behind a scope file"
```

---

