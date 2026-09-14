# Registry Census First Run Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute and publish the first real census of the official MCP Registry — Tier 1 (full pagination) + Tier 2 (static artifact analysis of the top-N packages per ecosystem) — under a dated `docs/census/<date>/` directory, with every published figure reproducible from the raw CSV alone.

**Architecture:** Nothing new is built. The pipeline already exists and is tested: `agent-perimeter census` (`agent_perimeter/cli.py:261`) calls `run_census` (`agent_perimeter/census/run.py:94`), which paginates the registry, ranks packaged entries by download count, fetches and statically analyses the top-N per ecosystem, and persists `CensusRun`/`CensusRecord` rows; `render_census`/`export_raw` (`agent_perimeter/report/census_report.py`) then write `census.html`, `records.csv`, `records.summary.json`. This plan adds one lock-in test for the publication layout, does a small-N dry run to measure real behaviour before the full run, runs the full census, verifies it, and records the publication.

**Tech Stack:** Python 3.12, `uv`, typer CLI, httpx, SQLAlchemy (SQLite for the dry run, the compose Postgres for the real run), stdlib-only `analysis/census_analysis.py`.

**Spec:** `docs/open-decisions.md` decision 5 (brief `01` §13.5), `docs/census/CHANGELOG.md` "When the first real run publishes" list, and `CLAUDE.md` hard rules 2, 3, 8 plus "Registry collection" under *Watch for*.

## Global Constraints

- Hard rule 2: public-registry scanning is **passive only** — registry API, package registries, cloned/downloaded artifacts. Never invoke a tool on, or send an MCP request to, a third-party server. Tier 3 (`agent_perimeter/census/tier3.py`) stays **unwired** for this run.
- Hard rule 3: no raw secret is persisted/logged/emitted. Nothing in this plan touches secret detection; the census records SDK version and feature flags only.
- Hard rule 8: **no named third-party server in the public report.** `records.csv` is keyed by salted digest; `package_name` lives only in the Postgres row and must never appear under `docs/census/`.
- "Registry collection: respect `robots.txt` and rate limits, identify with a contact URL, record fetch failures as part of the sample description." Already implemented (`fetch.MIN_INTERVAL_S = 0.5`, `sample.MIN_INTERVAL_S = 0.3`, `USER_AGENT` carries `https://github.com/Berakhah/agent-perimeter/blob/main/docs/security.md`); this plan verifies rather than re-implements.
- Copy rule: an empty stratum reads "not yet run" / "No findings for the checks that ran" — never a reassuring phrasing.
- Results are versioned, never overwritten: a correction is a new dated directory and a new changelog entry, never an edit to an old one.
- The report is the marketing (CLAUDE.md "Definition of done") — it must state sample, population, method, collection window, term definitions, raw data and the analysis script.
- `uv run ruff check`, `uv run ruff format --check`, `uv run mypy --strict` clean on every commit. Coverage floor 75%.
- Commit attribution: end commit messages with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

**Two things only the human partner can do, and when:** (1) confirm before Task 3's dry run — it is the first time this codebase contacts the live registry, pypistats.org and api.npmjs.org from this machine, even though it is passive; (2) confirm before Task 4's full run for the same reason plus its duration. Each is a stop point in the task below.

---

### Task 1: Lock in the publication layout with a test

A published run is a dated directory under `docs/census/` holding exactly `census.html`, `records.csv`, `records.summary.json`, and the CHANGELOG must name that date. Nothing enforces this today; once the first run lands, drift here is a reproducibility-claim failure. Write the test first — it passes trivially now (no dated directories exist) and becomes load-bearing the moment Task 5 publishes.

**Files:**
- Create: `tests/docs/test_census_publication.py`
- Read only: `docs/census/CHANGELOG.md`, `analysis/census_analysis.py`

**Interfaces:**
- Consumes: `analysis.census_analysis.check(csv_path: Path, summary_path: Path | None) -> bool` (stdlib-only module, imported by path below because `analysis/` is not a package).
- Produces: nothing importable; Task 5 relies on this test staying green after publication.

- [ ] **Step 1: Write the tests**

```python
"""Every published census run under docs/census/<date>/ must be complete,
reproducible from its own CSV, name-free, and recorded in the changelog."""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

CENSUS_DIR = Path("docs/census")
CHANGELOG = CENSUS_DIR / "CHANGELOG.md"
REQUIRED_FILES = ("census.html", "records.csv", "records.summary.json")
DATED = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _published_runs() -> list[Path]:
    return sorted(p for p in CENSUS_DIR.iterdir() if p.is_dir() and DATED.match(p.name))


def _analysis_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "census_analysis", Path("analysis/census_analysis.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_published_run_carries_the_three_artifacts() -> None:
    for run in _published_runs():
        for name in REQUIRED_FILES:
            assert (run / name).is_file(), f"{run.name} is missing {name}"


def test_every_published_run_is_named_in_the_changelog() -> None:
    body = CHANGELOG.read_text(encoding="utf-8")
    for run in _published_runs():
        assert f"## {run.name}" in body, f"CHANGELOG has no entry for {run.name}"


def test_every_published_csv_reproduces_its_own_summary() -> None:
    check = _analysis_module().check
    for run in _published_runs():
        assert check(run / "records.csv", run / "records.summary.json"), (
            f"{run.name}: records.csv does not reproduce records.summary.json"
        )


def test_published_csv_carries_digests_only() -> None:
    """Hard rule 8: no package name, URL, or registry id reaches the public CSV."""
    for run in _published_runs():
        header, *rows = (run / "records.csv").read_text(encoding="utf-8").splitlines()
        assert header == (
            "coords_digest,stratum,ecosystem,sdk_version,"
            "supports_2026_07_28,fetch_status,collected_at"
        )
        for row in rows:
            digest = row.split(",", 1)[0]
            assert re.fullmatch(r"[0-9a-f]{32}", digest), f"{run.name}: non-digest key {digest!r}"
            assert "http" not in row and "/" not in row.split(",", 1)[0]


def test_unreleased_section_is_honest_when_nothing_is_published() -> None:
    body = CHANGELOG.read_text(encoding="utf-8")
    if not _published_runs():
        assert "No census has been published yet" in body
```

- [ ] **Step 2: Run the tests — all should pass vacuously (no dated dirs yet)**

Run: `uv run pytest tests/docs/test_census_publication.py -v --no-cov`
Expected: 5 passed.

- [ ] **Step 3: Prove the test bites — create a fake incomplete run, run, delete it**

```powershell
New-Item -ItemType Directory -Force docs/census/1999-01-01 | Out-Null
uv run pytest tests/docs/test_census_publication.py -v --no-cov
Remove-Item -Recurse -Force docs/census/1999-01-01
```
Expected on the middle line: `test_every_published_run_carries_the_three_artifacts` FAILS with "1999-01-01 is missing census.html", and `test_every_published_run_is_named_in_the_changelog` FAILS. After removal, `git status` shows no stray directory.

- [ ] **Step 4: Lint, type-check, commit**

```bash
uv run ruff check tests/docs/test_census_publication.py && uv run ruff format tests/docs/test_census_publication.py && uv run mypy --strict tests/docs/test_census_publication.py
git add tests/docs/test_census_publication.py
git commit -m "test: lock in the census publication layout before the first run

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Retire the stale placeholder comment in the census User-Agent

`agent_perimeter/census/fetch.py:23-25` says the contact URL is "the same placeholder repo path as `agent_perimeter.cli.DEFAULT_CONTACT_URL`". That constant no longer exists (removed in `df224e5`) and the URL is real. A registry operator who reads this comment after seeing our User-Agent would reasonably conclude the contact is fake. Fold into a one-line fix.

**Files:**
- Modify: `agent_perimeter/census/fetch.py:21-27`

- [ ] **Step 1: Replace the comment**

```python
USER_AGENT = (
    f"agent-perimeter/{__version__} "
    # Contact URL for registry operators; the same value the transports send
    # (see transport/streamable_http.py). Kept as a literal so this read-only
    # fetch module does not import the CLI's typer/transport dependency graph.
    "(+https://github.com/Berakhah/agent-perimeter/blob/main/docs/security.md)"
)
```

- [ ] **Step 2: Confirm nothing asserts on the comment and the census tests still pass**

Run: `uv run pytest tests/census -q --no-cov`
Expected: all pass (the string constant is unchanged; only the comment moved).

- [ ] **Step 3: Commit**

```bash
git add agent_perimeter/census/fetch.py
git commit -m "docs: retire stale placeholder comment on the census User-Agent contact URL

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Dry run against the live registry at tiny N (STOP FOR GO-AHEAD FIRST)

Before the full run, measure the real population size, page count, pagination time, how many entries are packaged per ecosystem, and whether pypistats/npm throttle at the current intervals. Use a SQLite DB and a scratch output directory so nothing lands in `docs/census/` or the compose Postgres.

**Files:**
- No source changes. Output goes to the session scratchpad only.

**Interfaces:**
- Consumes: `agent-perimeter census --endpoint --tier2-n --out --database-url` (`agent_perimeter/cli.py:261`).
- Produces: measured numbers that Task 4 uses to size its timeout; nothing committed.

- [ ] **Step 1: Ask the human partner for go-ahead**

Say exactly what will happen: read-only GETs to `https://registry.modelcontextprotocol.io/v0/servers` (paginated, 100/page, 0.5 s between pages), one download-count GET per packaged entry to `pypistats.org` (0.3 s apart) or `api.npmjs.org`, and the artifact download of at most 2 packages per ecosystem. No MCP request to any server. Do not proceed without a yes.

- [ ] **Step 2: Run at `tier2_n=2` into scratch**

```powershell
$scratch = "$env:LOCALAPPDATA\Temp\claude\census-dryrun"
New-Item -ItemType Directory -Force $scratch | Out-Null
$t0 = Get-Date
uv run agent-perimeter census --tier2-n 2 --out "$scratch\out" --database-url "sqlite:///$scratch/dryrun.db"
"elapsed: $((Get-Date) - $t0)"
```
Expected output (values are what you record, not what you assert):
```
Population size: <P>
Tier-2 n:        2
Fetch failures:  <F>
Method hash:     <16 hex>
Report written to ...\out\census.html
Raw data written to ...\out\records.csv
```

- [ ] **Step 3: Record what the dry run measured**

From the SQLite DB, count packaged entries per ecosystem (this is the size of the download-count ranking pass, the dominant cost of the full run):

```powershell
uv run python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('select ecosystem, count(*) from census_records group by ecosystem').fetchall()); print(c.execute('select distribution, count(*) from census_records group by distribution').fetchall()); print(c.execute('select rank_metric_source, count(*) from census_records group by rank_metric_source').fetchall())" "$scratch\dryrun.db"
```

Write down: `P` (population), elapsed wall time, packaged count per ecosystem, count with `rank_metric_source = 'unavailable'` **among packaged entries** (a high share here means pypistats/npm throttled us and the ranking — hence the Tier 2 sample — is degraded), and `F`.

Estimated full-run time = dry-run elapsed + (artifact fetch of ~400 packages × ~2–5 s) — the ranking pass already ran in full during the dry run, since `rank()` looks up every packaged entry regardless of `tier2_n`.

- [ ] **Step 4: Decide whether the full run can proceed unchanged**

Proceed to Task 4 if: `F` is small relative to `P` (single digits, or clearly explained by `fetch_detail`), and `unavailable` among packaged PyPI entries is not the majority. If pypistats returned 429s for most PyPI entries, stop and raise `sample.MIN_INTERVAL_S` (currently 0.3) — that is a method change, so `method_hash()` will change, which is exactly why it exists; re-run the dry run before continuing.

- [ ] **Step 5: Verify the dry-run outputs are name-free and self-consistent**

```powershell
uv run python analysis/census_analysis.py "$scratch\out\records.csv"
Select-String -Path "$scratch\out\records.csv" -Pattern "http|@modelcontextprotocol|mcp-server" | Measure-Object
```
Expected: every line `match`; the `Select-String` count is 0.

- [ ] **Step 6: Clean up**

```powershell
Remove-Item -Recurse -Force $scratch
```
Nothing to commit.

---

### Task 4: The full run (STOP FOR GO-AHEAD FIRST)

**Files:**
- Create (generated, committed in Task 5): `docs/census/<YYYY-MM-DD>/census.html`, `docs/census/<YYYY-MM-DD>/records.csv`, `docs/census/<YYYY-MM-DD>/records.summary.json`

**Interfaces:**
- Consumes: the same CLI as Task 3, this time against the compose Postgres (`DEFAULT_DATABASE_URL`) so the `CensusRun` row, its salt, and every `package_name` stay queryable locally — the salt is what lets a maintainer later verify a digest under the disclosure policy (`docs/security.md` "Digest salt release").
- Produces: the three artifacts above, and the console summary lines Task 5 copies into the CHANGELOG.

- [ ] **Step 1: Ask the human partner for go-ahead, with the dry-run numbers**

State `P`, the packaged counts, and the estimated duration from Task 3. Default `tier2_n` is 200 per ecosystem; keep it unless the dry run showed fewer than 200 packaged entries in an ecosystem (then the top-N is the whole ecosystem and the report already says so). Do not proceed without a yes.

- [ ] **Step 2: Bring up Postgres and confirm migrations are current**

```powershell
docker compose up -d --wait db api
docker compose exec api alembic current
```
Expected: `db` and `api` healthy; `alembic current` prints the head revision.

- [ ] **Step 3: Run**

Use today's date (UTC) for the directory name. Run it in the background with a generous timeout so a long ranking pass does not kill the shell:

```powershell
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
uv run agent-perimeter census --out "docs/census/$date" 2>&1 | Tee-Object -FilePath "docs/census/$date/run.log"
```
Expected tail:
```
Population size: <P>
Tier-2 n:        200
Fetch failures:  <F>
Method hash:     <hash>
Report written to docs/census/<date>/census.html
Raw data written to docs/census/<date>/records.csv
```

- [ ] **Step 4: Verify reproducibility and name-freedom on the real output**

```powershell
uv run python analysis/census_analysis.py "docs/census/$date/records.csv"
Select-String -Path "docs/census/$date/records.csv" -Pattern "http|@|/" | Measure-Object
uv run pytest tests/docs/test_census_publication.py -v --no-cov
```
Expected: every analysis line `match`; `Select-String` count 0; the layout tests from Task 1 now exercise a real directory and all pass **except** `test_every_published_run_is_named_in_the_changelog`, which fails until Task 5 writes the entry — that failure is the RED step for Task 5.

- [ ] **Step 5: Read the rendered report as a sceptic would**

Open `docs/census/<date>/census.html` in a browser. Check that it states: the population definition and `P`; Tier 2's `n` **per ecosystem** (npm and PyPI never pooled into one figure); the live-discover section reads "not yet run"; fetch failures `F` are printed even if zero; the tool version and method hash; the collection window (run started/finished timestamps); every term used in a table is defined. Note anything missing — it belongs in the CHANGELOG entry as a stated limitation, not silently absent.

Delete `run.log` before committing (it may contain package names in `fetch_detail` lines):

```powershell
Remove-Item "docs/census/$date/run.log"
```

---

### Task 5: Record the publication

**Files:**
- Modify: `docs/census/CHANGELOG.md:8-34` (the `## Unreleased` block)
- Modify: `README.md` — the "registry census report" bullet under *Further reading*
- Modify: `docs/methodology.md` — wherever it says no census run has been published (grep `no run` / `not yet published`)
- Test: `tests/docs/test_census_publication.py` (from Task 1, now RED on the changelog check)

- [ ] **Step 1: Confirm the test is RED**

Run: `uv run pytest tests/docs/test_census_publication.py::test_every_published_run_is_named_in_the_changelog -v --no-cov`
Expected: FAIL, "CHANGELOG has no entry for <date>".

- [ ] **Step 2: Write the changelog entry**

Replace the `## Unreleased` block's first paragraph ("No census has been published yet…") with a pointer to the dated entry, keep the Tier 3 deferral note, and add the entry. Fill every `<…>` from Task 4's console output and `records.summary.json` — no placeholders may survive:

```markdown
## Unreleased

Nothing pending. Tier 3 (the live-discover stratum,
`agent_perimeter/census/tier3.py`) remains deliberately unwired — a
human-partner decision (2026-09-09, ratified in `docs/open-decisions.md`
decision 5): it makes real contact with third-party servers and has not been
through code review. Every published report's live-discover section reads
"not yet run".

## <YYYY-MM-DD>

First publication. Full census of the official MCP Registry
(`https://registry.modelcontextprotocol.io/v0/servers`), Tier 1 + Tier 2.

- **Population:** <P> registry entries observed, full pagination (<pages>
  pages of 100). Distribution: <n> `package_pypi`, <n> `package_npm`,
  <n> `package_other`, <n> `remote_only`, <n> `none`.
- **Tier 2 (static artifact analysis):** top 200 per ecosystem by download
  count — npm n = <n_npm examined>, PyPI n = <n_pypi examined>. Never pooled.
  Ranking source: pypistats.org recent downloads / api.npmjs.org last-month
  downloads; <n> packaged entries had no rank available and could not enter
  the top-N.
- **Tier 3 (live-discover):** did not run. See Unreleased.
- **Collection window:** <started_at> to <finished_at> UTC.
- **Tool version:** <tool_version>. **Method hash:** <method_hash>.
- **Fetch failures:** <F> (<registry page failures> registry pagination,
  <artifact failures> artifact fetch), stated as part of the sample.
- **Files:** `census.html` (report), `records.csv` (one row per record,
  salted-digest keyed, no names or URLs), `records.summary.json` (the
  report's figures). `uv run python analysis/census_analysis.py
  docs/census/<YYYY-MM-DD>/records.csv` reproduces every figure and reports
  `match` on every line as of this entry.
- **Limitations carried forward from `docs/methodology.md`:** the top-N
  sample is biased toward popular packages by construction and says nothing
  about the long tail; "supports 2026-07-28" is derived from SDK version
  floors and static feature detection, not observed behaviour; <anything
  the sceptic read in Task 4 Step 5 found missing>.
```

- [ ] **Step 3: Update README and methodology pointers**

README bullet — replace the "no run has been published yet" sentence:

```markdown
- **The registry census report** —
  [docs/census/<YYYY-MM-DD>/census.html](docs/census/<YYYY-MM-DD>/census.html),
  first published <YYYY-MM-DD>: a full census of the official MCP Registry
  (every entry, not a sample), with static artifact analysis of the top-N
  packages per ecosystem by download count — never a live contact with a
  third-party server. `docs/census/CHANGELOG.md` records population, window,
  method hash and fetch failures per run; `analysis/census_analysis.py`
  reproduces every published figure from `records.csv` alone.
```

In `docs/methodology.md`, find each statement that a run has not been published and point it at the dated entry the same way. Do **not** touch the CI-regenerated precision/recall table.

- [ ] **Step 4: Run the docs tests and the full suite**

```powershell
uv run pytest tests/docs -v --no-cov
uv run pytest -q
```
Expected: `tests/docs` all green including the five publication tests; full suite green with coverage ≥ 75%.

- [ ] **Step 5: Review what is about to be committed for names**

```powershell
git status
git diff --stat
Select-String -Path "docs/census/<YYYY-MM-DD>/*" -Pattern "@modelcontextprotocol|mcp-server-|github.com/(?!Berakhah)" | Measure-Object
```
Expected: exactly the three generated files plus CHANGELOG, README, methodology; `Select-String` count 0 (`census.html` may legitimately contain this project's own GitHub URL, hence the negative lookahead).

- [ ] **Step 6: Commit**

```bash
git add docs/census/<YYYY-MM-DD>/census.html docs/census/<YYYY-MM-DD>/records.csv docs/census/<YYYY-MM-DD>/records.summary.json docs/census/CHANGELOG.md README.md docs/methodology.md
git commit -m "docs: publish first registry census run (<YYYY-MM-DD>)

Full Tier 1 + Tier 2 census of the official MCP Registry; Tier 3 not run.
Every figure reproduces from records.csv via analysis/census_analysis.py.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-review

**Spec coverage.** Decision 5 (full Tier 1, Tier 1+2 only, Tier 3 unwired) → Task 4 uses the default CLI which never calls `tier3`; Task 5's entry states it did not run. CHANGELOG's "when the first real run publishes, its entry states at minimum" list — population with per-ecosystem Tier 2 n, whether Tier 3 ran, tool version + method hash, fetch failures + limitations — every item has a line in Task 5 Step 2. CLAUDE.md "Registry collection" bullet — rate limits and contact URL verified in Task 3 Step 3/4 and Task 2; fetch failures recorded in Task 5. Hard rule 8 — Task 1's digest-only test, Task 3 Step 5, Task 4 Step 4, Task 5 Step 5, and the `run.log` deletion. Definition-of-done report contents (sample, population, method, window, terms, raw data, script) — Task 4 Step 5 checks the rendered report; Task 5 records what was missing rather than hiding it.

**Placeholders.** The `<…>` tokens in Task 5 are values the executor reads off Task 4's output; Step 2 says none may survive. No "TBD"/"handle edge cases" language anywhere.

**Type consistency.** `check(csv_path, summary_path)` in Task 1 matches `analysis/census_analysis.py:144`. CSV header in Task 1 matches `export_raw` at `census_report.py:240-249`. CLI flags `--tier2-n`, `--out`, `--database-url` match `cli.py:261-270` (typer renders `tier2_n` as `--tier2-n`).

**Not in scope, deliberately.** Pushing the 64 unpushed commits (separate go-ahead), the clean-machine verification, and any change to `tier2_n`'s default or the ranking method unless Task 3 Step 4 forces it.
