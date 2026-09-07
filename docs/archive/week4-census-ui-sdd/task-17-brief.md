### Task 17: Compose, clean-machine verification, licence audit, release

**Files:**
- Modify: `docker-compose.yml`
- Create: `Dockerfile` (api), `web/Dockerfile`
- Create: `scripts/smoke.sh`
- Create: `docs/evidence/clean-machine.md`
- Create: `LICENSE`, `NOTICE`
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Interfaces:** none. This closes DoD 10 and flips the repo public.

- [ ] **Step 1: RED — the smoke script asserts, it does not narrate**

Create `scripts/smoke.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

fail() { echo "FAIL: $1" >&2; exit 1; }

curl -fsS localhost:8000/api/health >/dev/null || fail "api not healthy"
curl -fsS localhost:3000/ >/dev/null || fail "web not serving"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"python /server.py","mode":"active"}')
[ "$code" = "422" ] || fail "active scan without a scope file returned $code, expected 422"

docker compose exec -T api uv run alembic current | grep -q 0004 || fail "migrations not at head"

echo "OK: api, web, refusal path and migrations all verified"
```

The refusal assertion is in the smoke test deliberately. It is the constraint most likely to be broken by a deployment mistake rather than a code mistake, and a deployment mistake is exactly what a compose check catches.

- [ ] **Step 2: GREEN — compose**

`docker-compose.yml` with four services: `db` (postgres:16, healthcheck, named volume), `api` (depends_on `db` healthy, runs `alembic upgrade head` on start), `web` (depends_on `api`), and `fixture` (the parameterised MCP fixture server from Week 1 Task 6, for demos). No secrets in the file; `.env.example` carries every variable with a placeholder value.

- [ ] **Step 3: Verify on a genuinely clean machine**

Not the development machine. A fresh VM or a clean container with only Docker installed:

```bash
git clone <repo> && cd agent-perimeter
cp .env.example .env
docker compose up -d --wait
./scripts/smoke.sh
```

Record the full transcript in `docs/evidence/clean-machine.md` with the date, the host OS, the Docker version, and the elapsed time from clone to green. **If anything needed a step not in the README, add the step to the README rather than to the transcript.** That is the entire point of the exercise.

- [ ] **Step 4: Licence audit**

```bash
uv run pip-licenses --format=markdown --with-urls > docs/licences.md
cd web && npx license-checker --summary
```

Flag any AGPL, SSPL, BUSL or non-commercial dependency explicitly. Per `00` §3 and the global constraints, an AGPL dependency is flagged and removed, never adopted silently. Commit `docs/licences.md`.

- [ ] **Step 5: Licence files and the CLAUDE.md correction**

Add `LICENSE` (Apache-2.0 full text) and `NOTICE`. Week 1 Task 1 Step 6 already corrected `CLAUDE.md` line 4 from `Licence: TBD` to `Licence: Apache-2.0` — confirm it stuck:

```bash
grep -n "Licence:" CLAUDE.md
```

Expected: `Apache-2.0`, with no "open decision" text remaining.

- [ ] **Step 6: README**

The README is read by someone deciding in ninety seconds whether this is serious. It states: what it is, the one differentiator sentence, `docker compose up` quickstart, the CI usage snippet (SARIF upload to GitHub code scanning — that is the distribution channel), a link to `docs/methodology.md` with the precision/recall table, a link to the census report, a link to `docs/security.md`, and the scope-file requirement stated up front rather than discovered on first refusal.

- [ ] **Step 7: Final DoD sweep**

```bash
uv run pytest --cov=agent_perimeter --cov-report=term-missing
uv run mypy --strict agent_perimeter && uv run ruff check . && uv run ruff format --check .
cd web && npx tsc --noEmit && npm run lint && npx playwright test
```

Then walk the ten DoD items in brief §12 one at a time and name the test or artifact that closes each. An item with no named evidence is not done, whatever the plan says.

- [ ] **Step 8: Publish**

Flip the repository public (full history preserved — that was the basis of the decision), publish the census report to GitHub Pages, tag `v0.1.0`, and start the 90-day embargo clock on any maintainer contacts made during the census.

```bash
git add -A
git commit -m "chore: apache-2.0 licence, compose verification and v0.1.0 release prep"
git tag -a v0.1.0 -m "Agent Perimeter v0.1.0"
```

---

## Week 4 completion gate

- [ ] `uv run pytest` passes, coverage at or above 75%
- [ ] `mypy --strict`, `ruff check`, `ruff format --check` all clean
- [ ] `npx tsc --noEmit`, `npm run lint`, `npx playwright test` all clean
- [ ] Tiers 1–2 reach the registry, PyPI and npm only, and Tier 3 sends exactly one `server/discover` per sampled host and nothing else — both proven by `test_passive_only.py`, and **each** guard has been seen to fail when deliberately broken
- [ ] The Tier-3 seed, frame snapshot and opt-out list are published with the raw data, and `docs/security.md` was published before the first Tier-3 request went out
- [ ] No downloaded artifact is ever executed, imported or evaluated — proven by test
- [ ] Artifact-derived confidence is strictly below live-probe confidence — proven by test
- [ ] `fetch_failures` appears in the report even when zero
- [ ] Unknowns are reported separately and never folded into a denominator
- [ ] No third-party server name, registry id or URL appears in the rendered report or the raw data export — proven by test
- [ ] The word "vulnerable" does not appear in the census report — proven by test
- [ ] `analysis/census_analysis.py` reproduces every published figure from the published CSV alone
- [ ] Census report published with sample, population, method, collection window, term definitions, raw data and analysis script (**DoD 7 closed**)
- [ ] `docs/security.md` carries all seven required sections and matches the 90-day decision; `SECURITY.md` carries the same contact (**DoD 8 closed**)
- [ ] Six screens: zero serious or critical axe violations, full keyboard operation, visible focus rings, usable at 375px, `prefers-reduced-motion` respected, print correct in greyscale (**DoD 9 closed**)
- [ ] The API refuses an active scan without a scope file on exactly the same rule as the CLI, and `scripts/smoke.sh` asserts it
- [ ] `docker compose up` on a clean machine reaches green, transcript recorded in `docs/evidence/clean-machine.md` (**DoD 10 closed**)
- [ ] `docs/licences.md` generated; no AGPL, SSPL, BUSL or non-commercial dependency
- [ ] All ten DoD items in brief §12 walked one at a time with named evidence for each

## Next

Weeks 1–4 are planned end to end and this is the last plan document. Nothing further is written before implementation begins.

Execution starts at **Week 1 Task 1**, which is repo scaffolding and CI — and which also performs `git init`, since `agent-perimeter/` is not yet a git repository.

Two things carry out of this repo into other sessions and should be raised there before those repos are built:

- **`bok-core`** — the six requirements in spec §8 (Claim derivation granularity, `boundary/fingerprint.py`, SARIF `logicalLocations`, enforced `tools_disabled` in the gateway, calibration state on `Claim`, and per-class scoring).
- **`bok-ui`** — the three requirements in Task 10 (`Claim` derivation prop, provenance column surviving CSV export, uncalibrated as `ConfidenceMeter`'s default state).

Both are contracts specified here and built there. Until they ship, `agent_perimeter/_contracts.py` and `web/src/lib/_bok-ui.tsx` stand in, each marked with its swap path.
