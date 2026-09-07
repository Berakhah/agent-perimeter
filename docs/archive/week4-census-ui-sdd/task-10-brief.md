### Task 10: Web scaffold, tokens and the `bok-ui` contract

**Files:**
- Create: `web/package.json`, `web/tsconfig.json`, `web/next.config.ts`, `web/app/layout.tsx`, `web/app/globals.css`
- Create: `web/src/lib/_bok-ui.tsx`
- Create: `web/src/lib/api.ts`
- Create: `web/src/fonts/` (self-hosted Newsreader, Geist Sans, IBM Plex Mono)
- Test: `web/tests/tokens.spec.ts`

**Interfaces:**
- Produces: local stand-ins for `Claim`, `ProvenanceRail`, `SeverityBadge`, `FindingsTable`, `EvidencePane`, `ConfidenceMeter`, `QuotaStrip`, `RunTimeline`, `DiffView`, `EmptyState`, `ErrorState`, `Skeleton`; typed `api` client.
- Consumes: the Task 9 API.

`bok-ui` does not exist yet. This mirrors exactly what Week 1 Task 2 did for `bok-core`: `web/src/lib/_bok-ui.tsx` holds real implementations of the twelve components against the interface `00` §5.4 specifies, each marked with the swap path. When the package ships, the import changes from `@/lib/_bok-ui` to `@backoffice-kit/bok-ui` and the file is deleted.

**Requirements on `bok-ui`, to carry to the `backoffice-kit` session** — additions to `00` §5.4 that this project needs and the shared foundation does not currently specify:

1. `Claim` must accept a `derivation` prop (`schema` / `description` / `probe` / `artifact`) and render the four distinguishably. This is `bok-core` requirement 1 surfacing in the UI layer; without it the capability graph cannot honour B9.
2. `FindingsTable` needs a column type for provenance state that is glyph-plus-label, not colour, and it must survive CSV export — an export that drops the provenance column exports a claim without its basis.
3. `ConfidenceMeter` must render an uncalibrated score greyed and labelled without the caller having to remember to pass a flag: **uncalibrated is the default state**, and calibration is what has to be supplied.

- [ ] **Step 1: Scaffold**

```bash
cd web
npx create-next-app@latest . --typescript --tailwind --app --eslint --no-src-dir --use-npm
npm i -D @axe-core/playwright @playwright/test
```

Set `"strict": true` and `"noUncheckedIndexedAccess": true` in `tsconfig.json`.

- [ ] **Step 2: Fonts, self-hosted**

Download Newsreader, Geist Sans and IBM Plex Mono into `web/src/fonts/` and load them with `next/font/local`. **No Google Fonts CDN call** — `00` §5.2 names it a privacy and offline-demo liability, and an offline demo is a real scenario for this buyer.

- [ ] **Step 3: RED — the token test**

Create `web/tests/tokens.spec.ts`:

```ts
import { expect, test } from "@playwright/test";

test("severity is never encoded in colour alone", async ({ page }) => {
  await page.goto("/findings?fixture=mixed");
  for (const row of await page.getByRole("row").all()) {
    const badge = row.getByTestId("severity-badge");
    if (await badge.count()) {
      await expect(badge).toHaveAttribute("data-glyph", /.+/);
      await expect(badge).not.toHaveText("");
    }
  }
});

test("numbers are tabular", async ({ page }) => {
  await page.goto("/findings?fixture=mixed");
  const cell = page.getByTestId("numeric-cell").first();
  await expect(cell).toHaveCSS("font-variant-numeric", /tabular-nums/);
});

test("no external host is contacted", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    const url = new URL(r.url());
    if (!["localhost", "127.0.0.1"].includes(url.hostname)) external.push(r.url());
  });
  await page.goto("/");
  expect(external).toEqual([]);
});
```

- [ ] **Step 4: GREEN — tokens in `globals.css`**

Define the OKLCH ramp from `00` §5.2 as custom properties consumed through Tailwind v4 `@theme`: paper `oklch(0.985 0.004 85)`, ink `oklch(0.22 0.012 85)`, twelve neutral steps, accent signal amber `oklch(0.72 0.16 68)`, semantic severity and provenance scales. `font-variant-numeric: tabular-nums` on every numeric cell class. Three density modes, defaulting to `compact`.

- [ ] **Step 5: Commit**

```bash
cd web && npm run lint && npx tsc --noEmit && npx playwright test tests/tokens.spec.ts
git add web/
git commit -m "feat: web scaffold with self-hosted fonts and bok-ui stand-ins"
```

---

