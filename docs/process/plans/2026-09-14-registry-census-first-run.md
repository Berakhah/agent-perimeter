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

### Task 6: Fail loudly on truncated pagination; retry pypistats on 429 (executes between Task 3 and Task 4)

Added 2026-09-14 after the Task 3 dry run. Two findings: (a) a transient failure on registry page 3 made `paginate` return silently, and the run recorded `population_size = 200` as though the registry had been exhausted — a truncated census must never be reportable as complete; (b) pypistats.org returned 429 on 3 of 6 probes at `MIN_INTERVAL_S = 0.3`, and `_pypi_downloads` never retries, so most PyPI entries come back `UNAVAILABLE` and can never enter the Tier 2 top-N. Both are method changes; `method_hash()` will change, which is intended.

**Files:**
- Modify: `agent_perimeter/census/fetch.py` (`_get_page`, `paginate`, new exception)
- Modify: `agent_perimeter/census/sample.py` (`MIN_INTERVAL_S`, `_pypi_downloads`)
- Modify: `agent_perimeter/cli.py:294-295` (catch the new exception, exit non-zero)
- Test: `tests/census/test_fetch.py`, `tests/census/test_sample.py` (follow the existing fixtures/transport-mocking pattern in those files)

**Interfaces:**
- Produces: `agent_perimeter.census.fetch.PaginationTruncated(RuntimeError)` with attributes `page: int`, `entries_seen: int`, `detail: str`; raised by `paginate` instead of returning early. `run_census` lets it propagate (its `CensusRun` row is never committed — the session rolls back). `cli.census` catches it and prints `Census aborted: registry pagination failed at page {page} after {entries_seen} entries — {detail}. Nothing written.` then `raise typer.Exit(code=1)`.

- [ ] **Step 1: Write the failing pagination tests**

In `tests/census/test_fetch.py`, using the same mock-transport helper the file already uses for `paginate`:

```python
def test_a_page_failure_after_retries_raises_instead_of_truncating(...) -> None:
    # pages 1 and 2 return 100 entries each with a nextCursor; page 3 returns 500 on every attempt
    with pytest.raises(PaginationTruncated) as excinfo:
        list(fetch.paginate(client, ENDPOINT, log, max_retries=3))
    assert excinfo.value.page == 3
    assert excinfo.value.entries_seen == 200
    assert "page 3" in excinfo.value.detail


def test_a_transient_5xx_is_retried_and_the_population_is_complete(...) -> None:
    # page 3 returns 503 once, then 200 with 20 entries and no cursor
    entries = list(fetch.paginate(client, ENDPOINT, log, max_retries=3))
    assert len(entries) == 220
    assert log.failures == 0


def test_full_first_page_without_cursor_raises(...) -> None:
    # page 1 returns exactly PAGE_LIMIT entries and no metadata.nextCursor
    with pytest.raises(PaginationTruncated) as excinfo:
        list(fetch.paginate(client, ENDPOINT, log))
    assert excinfo.value.page == 1
```

Monkeypatch `fetch.time.sleep` to a no-op in these tests so backoff does not slow the suite.

- [ ] **Step 2: Run them — expect NameError/ImportError on `PaginationTruncated` and the first test to see a plain return**

Run: `uv run pytest tests/census/test_fetch.py -q --no-cov`

- [ ] **Step 3: Implement in `fetch.py`**

```python
class PaginationTruncated(RuntimeError):
    """A page failed after every retry. The entries read so far are a prefix of
    the population, not the population - never report them as one."""

    def __init__(self, page: int, entries_seen: int, detail: str) -> None:
        super().__init__(f"page {page}: {detail} (after {entries_seen} entries)")
        self.page = page
        self.entries_seen = entries_seen
        self.detail = detail
```

In `_get_page`: treat `response.status_code >= 500` the same way as a timeout — retry up to `max_retries`, sleeping `MIN_INTERVAL_S * 2**attempt` between attempts, and log `FetchStatus.PARSE_ERROR` with `f"page {page}: status {status}, gave up after {max_retries} attempts"` only when retries are exhausted. Add the same backoff sleep to the existing timeout-retry path. Non-429 4xx stays an immediate failure. Also record the last detail string on the log call so `paginate` can put it in the exception — simplest: have `_get_page` return `tuple[dict[str, object] | None, str | None]` (body, failure detail) instead of a bare body.

In `paginate`: when `_get_page` reports failure, `raise PaginationTruncated(page, len(seen_names), detail)`. In the existing page-1 full-page-no-cursor guard, keep the log line and then `raise PaginationTruncated(1, len(seen_names), "...same message...")` instead of `return`.

- [ ] **Step 4: Write the failing pypistats tests**

In `tests/census/test_sample.py`, following the file's existing `_pypi_downloads` mocking pattern:

```python
def test_pypi_429_is_retried_with_backoff_then_succeeds(monkeypatch, ...) -> None:
    # responses: 429, 429, 200 {"data": {"last_month": 123}}
    sleeps: list[float] = []
    monkeypatch.setattr(sample.time, "sleep", sleeps.append)
    assert sample._pypi_downloads(client, "pkg") == 123
    assert sleeps == list(sample.PYPI_429_BACKOFF_S[:2])


def test_pypi_429_on_every_attempt_is_unavailable(monkeypatch, ...) -> None:
    # responses: 429 x (1 + len(PYPI_429_BACKOFF_S))
    monkeypatch.setattr(sample.time, "sleep", lambda _s: None)
    assert sample._pypi_downloads(client, "pkg") is None
```

- [ ] **Step 5: Implement in `sample.py`**

```python
MIN_INTERVAL_S = 1.0  # was 0.3; pypistats.org 429'd 3 of 6 probes at 0.3s on 2026-09-14
PYPI_429_BACKOFF_S: tuple[float, ...] = (2.0, 5.0, 10.0)
```

In `_pypi_downloads`: loop over `range(len(PYPI_429_BACKOFF_S) + 1)`; on 429 and attempts remaining, `time.sleep(PYPI_429_BACKOFF_S[attempt])` and retry; on the final 429 return `None`. Every other outcome keeps its current handling. Update the module comment above `MIN_INTERVAL_S` to state the measured 2026-09-14 result instead of the 2026-09-03 one.

- [ ] **Step 6: CLI**

In `cli.census`, wrap the `run_census(...)` call:

```python
        try:
            run = run_census(session, client, endpoint=endpoint, tier2_n=tier2_n)
        except PaginationTruncated as exc:
            typer.echo(
                f"Census aborted: registry pagination failed at page {exc.page} after "
                f"{exc.entries_seen} entries - {exc.detail}. Nothing written.",
                err=True,
            )
            raise typer.Exit(code=1) from exc
```

Import `PaginationTruncated` alongside `run_census` inside the function. Add one CLI test in `tests/test_cli.py` (or wherever `census` is already tested — grep for `"census"`) that monkeypatches `run_census` to raise and asserts exit code 1 and that no `census.html` was written to `--out`.

- [ ] **Step 7: Full census + CLI tests, lint, type-check, commit**

```bash
uv run pytest tests/census tests/test_cli.py -q --no-cov
uv run ruff check agent_perimeter tests && uv run ruff format --check agent_perimeter tests && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/fetch.py agent_perimeter/census/sample.py agent_perimeter/cli.py tests/census/test_fetch.py tests/census/test_sample.py tests/test_cli.py
git commit -m "fix: census refuses to report a truncated population; pypistats ranking retries on 429

A transient page failure made paginate() return silently and the run
recorded the prefix as population_size. Now raises PaginationTruncated
and the CLI exits 1 with nothing written. pypistats.org throttled 3/6
probes at 0.3s; interval is 1.0s with 2/5/10s backoff on 429.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 8: Re-run Task 3's dry run** (Steps 2–6 of Task 3, go-ahead already given) and confirm: population is well above 200 with `exhausted after N pages` in the log, and PyPI `unavailable` is no longer the majority.

### Task 7: Tier 2 selection becomes a seeded random sample; progress output; client timeout (executes after Task 6, before Task 4)

Added 2026-09-14 after the Task 6 re-run. Measured: the registry holds **31,928** entries (17,879 remote-only, 8,590 npm, 3,651 PyPI, 1,352 other, 456 none); pagination alone takes ~7 min with 0 failures. `sample.rank` looks up every one of the 12,241 packaged entries at pypistats.org / api.npmjs.org before `top_n` runs — at ≥1 s per PyPI call (18 s when throttled, and pypistats throttles almost at once) that is hours, and the 6-hour dry run never finished. Human-partner decision 2026-09-14: **Tier 2 is a seeded uniform random sample of n per ecosystem**, no download ranking at all. This is statistically cleaner (an unbiased estimate of the ecosystem's share instead of a popularity-weighted one), removes two network hosts from the passive census, and drops the run to minutes. The report's prose and term definitions change to match. `method_hash()` changes — intended.

Also: `run_census` gains progress output so a long run is never a black box, and the CLI's `httpx.Client` gets a default timeout.

**Files:**
- Rewrite: `agent_perimeter/census/sample.py`
- Modify: `agent_perimeter/census/run.py` (`run_census`, `_record_for`)
- Modify: `agent_perimeter/db/models.py` (`CensusRun.sample_seed`)
- Create: `migrations/versions/0004_census_sample_seed.py` (revision `'0004'`, down_revision `'0003'`; follow `0003_census.py`'s style)
- Modify: `agent_perimeter/cli.py` (`census` command: `--seed`, progress echo, client timeout)
- Modify: `agent_perimeter/report/census_report.py` (`TERM_DEFINITIONS["sample"]`, summary JSON `sample_seed`), `agent_perimeter/report/templates/census.html.j2` (lines 71-74 prose; add seed to the run table)
- Modify: `agent_perimeter/api/census.py` (expose `sample_seed` next to `tier2_n`), `web/src/lib/api.ts` (add `sample_seed: number | null` to the census run type)
- Test: `tests/census/test_sample.py` (rewrite), `tests/census/test_run.py`, `tests/census/test_passive_only.py`, `tests/report/test_census_report.py`, `tests/test_cli.py`
- Do NOT touch: `analysis/census_analysis.py` (it recomputes from `records.csv`, which does not change shape), `docs/` (Task 5 owns the docs).

**Interfaces:**
- Produces: `sample.select(entries: list[RegistryEntry], n: int, seed: int) -> list[RegistryEntry]`; `sample.SELECTION_SOURCE = "seeded_random"`; `sample.SELECTION_METHOD` (new text below); `run_census(session, client, *, endpoint, tier2_n, seed: int | None = None, progress: Callable[[str], None] | None = None) -> CensusRun`; `CensusRun.sample_seed: int | None`; CLI `--seed INT` (optional; generated when absent) and a `Sample seed:     {seed}` console line; `records.summary.json` gains top-level `"sample_seed"`.
- Removes: `RankSource`, `RankedEntry`, `rank`, `top_n`, `_pypi_downloads`, `_npm_downloads`, `PYPI_DOWNLOADS`, `NPM_DOWNLOADS`, `MIN_INTERVAL_S`, `PYPI_429_BACKOFF_S`, `USER_AGENT` and the `httpx`/`time` imports from `sample.py`. `CensusRecord.rank_metric` stays in the schema (always `None` now); `rank_metric_source` is `SELECTION_SOURCE` for selected entries and `None` otherwise.

- [ ] **Step 1: Failing tests for `select`** (`tests/census/test_sample.py` — replace the file; use `tests/census/factories.py` to build `RegistryEntry` objects with npm/PyPI coords and without coords)

```python
def test_same_seed_and_population_gives_the_same_selection() -> None:
    entries = [...]  # 30 npm, 20 pypi, 10 remote-only, distinct registry_ids
    a = sample.select(entries, n=5, seed=42)
    b = sample.select(list(reversed(entries)), n=5, seed=42)
    assert [e.registry_id for e in a] == [e.registry_id for e in b]


def test_different_seeds_give_different_selections() -> None:
    entries = [...]  # 200 npm entries
    assert {e.registry_id for e in sample.select(entries, n=20, seed=1)} != {
        e.registry_id for e in sample.select(entries, n=20, seed=2)
    }


def test_n_is_per_ecosystem_and_capped_by_the_pool() -> None:
    entries = [...]  # 30 npm, 3 pypi
    chosen = sample.select(entries, n=5, seed=7)
    by_eco = Counter(e.coords.ecosystem for e in chosen if e.coords is not None)
    assert by_eco == {Ecosystem.NPM: 5, Ecosystem.PYPI: 3}


def test_entries_without_coords_are_never_selected() -> None:
    entries = [...]  # 10 remote-only, 2 npm
    assert all(e.coords is not None for e in sample.select(entries, n=50, seed=0))


def test_sample_module_makes_no_network_calls() -> None:
    src = Path("agent_perimeter/census/sample.py").read_text(encoding="utf-8")
    assert "httpx" not in src and "https://" not in src
```

Determinism must not depend on input order: sort the pool by `registry_id` before sampling.

- [ ] **Step 2: Run — expect AttributeError on `sample.select`**

- [ ] **Step 3: Implement `sample.py`**

```python
"""Tier-2 selection: a seeded uniform random sample per ecosystem.

The registry API carries no popularity signal, and ranking every packaged
entry against pypistats.org / api.npmjs.org took hours against the real
population (12,241 packaged entries on 2026-09-14) while pypistats throttled
most calls. A seeded random sample needs no network at all, and it estimates
an ecosystem's share without weighting toward popular packages.
"""

from __future__ import annotations

import random

from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.model.census import Ecosystem

SELECTION_SOURCE = "seeded_random"

SELECTION_METHOD = (
    "Tier 2 is a uniform random sample of up to n packaged entries within each "
    "ecosystem, drawn with a recorded seed so the same population and seed "
    "reproduce the same sample. Ecosystems are sampled separately because npm and "
    "PyPI are different populations. Entries with no fetchable package coordinates "
    "(remote-only, or a package type this tool does not model) are not eligible and "
    "are counted in the report. The registry itself carries no popularity signal, "
    "and this sample is not weighted by downloads, stars, or any proxy for use."
)


def select(entries: list[RegistryEntry], n: int, seed: int) -> list[RegistryEntry]:
    rng = random.Random(seed)
    out: list[RegistryEntry] = []
    for eco in Ecosystem:
        pool = sorted(
            (e for e in entries if e.coords is not None and e.coords.ecosystem is eco),
            key=lambda e: e.registry_id,
        )
        out.extend(rng.sample(pool, min(n, len(pool))))
    return out
```

- [ ] **Step 4: Failing tests for `run_census`** (`tests/census/test_run.py` — adjust the existing tests that assert on `rank_metric`/`rank_metric_source`; add)

```python
def test_run_persists_the_seed_and_marks_selected_records() -> None:
    run = run_census(session, client, endpoint=ENDPOINT, tier2_n=2, seed=99)
    assert run.sample_seed == 99
    selected = [r for r in records(run) if r.rank_metric_source == sample.SELECTION_SOURCE]
    assert len(selected) == <expected per fixture>
    assert all(r.rank_metric is None for r in records(run))


def test_run_generates_a_seed_when_none_is_given() -> None:
    run = run_census(session, client, endpoint=ENDPOINT, tier2_n=2)
    assert isinstance(run.sample_seed, int)


def test_run_reports_progress() -> None:
    lines: list[str] = []
    run_census(session, client, endpoint=ENDPOINT, tier2_n=2, progress=lines.append)
    assert any("population" in line for line in lines)
    assert any("artifact" in line for line in lines)
```

- [ ] **Step 5: Implement `run.py`, `models.py`, migration**

`run_census` signature per Interfaces. Body: after `run.population_size = len(entries)`, `_say(f"population: {len(entries)} entries")`; `seed = secrets.randbits(32) if seed is None else seed`; `run.sample_seed = seed`; `selected = {e.registry_id for e in sample.select(entries, tier2_n, seed)}`; `_say(f"tier 2: selected {len(selected)} packaged entries with seed {seed}")`; in the loop, count artifact fetches and `_say(f"artifacts: {done}/{len(selected)}")` every 25 and at the end. `_say` is `progress or (lambda _m: None)`. `_record_for(run, entry, selected, salt)`: `rank_metric=None`, `rank_metric_source=sample.SELECTION_SOURCE if entry.registry_id in selected else None`. Remove the `sample.rank`/`top_n` calls and `RankedEntry` import.

`models.py`: `sample_seed: Mapped[int | None] = mapped_column(BigInteger, nullable=True)` on `CensusRun`, after `salt`. Migration `0004`: `op.add_column('census_run', sa.Column('sample_seed', sa.BigInteger(), nullable=True))` / `op.drop_column('census_run', 'sample_seed')`.

- [ ] **Step 6: CLI, report, API**

`cli.census`: add `seed: Annotated[int | None, typer.Option(help="Tier-2 sample seed; generated and printed when omitted.")] = None`; `httpx.Client(timeout=30.0)`; pass `seed=seed, progress=lambda m: typer.echo(m, err=True)`; after `Tier-2 n:` echo `f"Sample seed:     {run.sample_seed}"`. Add a CLI test that passes `--seed 5` with `run_census` monkeypatched to capture kwargs and asserts `seed == 5`.

`census_report.py`: `TERM_DEFINITIONS["sample"]` = `"Tier 1 is the whole population. Tier 2 is a seeded uniform random sample of up to n packaged entries within each ecosystem, selected as described under Method."`; add `"sample_seed": run.sample_seed` to the summary dict in `export_raw`. Template lines 71-74 → `Tier-2 target n is per ecosystem, not pooled: up to <span data-testid="tier2-n">{{ run.tier2_n }}</span> npm packages and up to {{ run.tier2_n }} PyPI packages are independently drawn at random (seed {{ run.sample_seed }}) within each ecosystem before any artifact is fetched.` Add a `<tr><th>Sample seed</th><td class="num" data-testid="sample-seed">{{ run.sample_seed }}</td></tr>` row to the run table next to Population. Extend `tests/report/test_census_report.py` (the factory there sets `rank_metric=None`; add `sample_seed=` to the run factory) with one assertion that the rendered HTML contains the seed and that `records.summary.json` carries `sample_seed`.

`api/census.py`: add `"sample_seed": run.sample_seed` next to `"tier2_n"`; `web/src/lib/api.ts`: `sample_seed: number | null;` next to `tier2_n`.

`tests/census/test_passive_only.py:183-190`: remove `"pypistats.org"` and `"api.npmjs.org"` from `allowed` and update the docstring's "five hosts" wording — the passive census now contacts three.

- [ ] **Step 7: Full census/report/CLI tests, lint, type-check, commit**

```bash
uv run pytest tests/census tests/report tests/test_cli.py tests/api -q --no-cov
uv run ruff check agent_perimeter tests migrations && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/sample.py agent_perimeter/census/run.py agent_perimeter/db/models.py migrations/versions/0004_census_sample_seed.py agent_perimeter/cli.py agent_perimeter/report/census_report.py agent_perimeter/report/templates/census.html.j2 agent_perimeter/api/census.py web/src/lib/api.ts tests/census tests/report tests/test_cli.py
git commit -m "feat: tier-2 census sample is a seeded random draw per ecosystem, not a download ranking

Ranking all 12,241 packaged registry entries via pypistats/npm took hours
and pypistats throttled most calls. A seeded uniform sample needs no
network, is reproducible from the recorded seed, and does not weight by
popularity. Adds progress output and a CLI client timeout.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

`ruff format --check` must be clean on every file this commit touches (there is pre-existing drift in files it does not touch — leave those alone).

- [ ] **Step 8: Re-run Task 3's dry run** (`--tier2-n 2 --seed 1`, go-ahead already given) in the foreground with a 15-minute timeout and confirm: population ≈ 32k with 0 pagination failures, `Sample seed: 1`, 4 artifacts fetched, analysis script all `match`, CSV name-free, elapsed under ~10 min.

### Task 8: Detect the SDK pin where real artifacts actually keep it (executes after the first full run, before Task 5; the full run is then repeated)

Added 2026-09-14 after the first full run. Result: 364 of 387 fetched artifacts (94%) classified `unknown` with caveat "no SDK pin and no parseable source", and `sdk_version` was `None` for **all 387** — including 194 npm packages. Verified against real packages: `@modelcontextprotocol/server-filesystem` (npm) extracts to `root/package/package.json`; `mcp-server-fetch` (PyPI sdist) extracts to `root/mcp_server_fetch-2026.8.18/pyproject.toml` (+ `PKG-INFO`); a wheel carries its requirements in `root/<name>-<ver>.dist-info/METADATA` as `Requires-Dist:` lines. `detect_sdk_pin` and `_ecosystem_of` (`agent_perimeter/census/detect.py:169-201`) only ever look at `root/` itself, so the pin is never found on a real artifact. The fixture tests all put manifests at the root and never caught it. Publishing "94% unknown" caused by this would be the exact credibility failure CLAUDE.md's "false positives end credibility" warning describes, in mirror image.

**Files:**
- Modify: `agent_perimeter/census/detect.py` (`_pin_from_requirement`, `detect_sdk_pin`, `_ecosystem_of`; new `_manifest_dirs`, `_pin_from_metadata`)
- Test: `tests/census/test_detect.py` (follow its existing tmp-tree fixture style)
- Do NOT touch: `docs/`, the report, the CLI.

**Interfaces:**
- `detect_sdk_pin(root: Path) -> str | None` and `detect_features(root)` keep their signatures. Behaviour change: manifests are found in `root` **or any immediate subdirectory of `root`** (one level only), and PyPI pins are also read from `PKG-INFO` (sdist) and `*.dist-info/METADATA` (wheel) `Requires-Dist:` lines. `method_hash()` changes — intended.

- [ ] **Step 1: Failing tests** (`tests/census/test_detect.py`; build trees under `tmp_path`)

```python
def test_npm_pin_is_found_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.12.0"}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.12.0"


def test_pypi_pin_is_found_in_a_versioned_sdist_directory(tmp_path: Path) -> None:
    d = tmp_path / "mcp_server_x-2026.8.18"
    d.mkdir()
    (d / "pyproject.toml").write_text('[project]\ndependencies = ["mcp>=1.2.0"]\n', encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) == "1.2.0"


def test_pypi_pin_is_read_from_sdist_pkg_info(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text("Name: x\nRequires-Dist: httpx\nRequires-Dist: mcp>=2.1\n", encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) == "2.1"


def test_pypi_pin_is_read_from_wheel_metadata(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_text("Name: x\nRequires-Dist: mcp>=2.0.0; python_version >= \"3.10\"\n", encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) == "2.0.0"


def test_environment_marker_version_is_not_mistaken_for_the_pin(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text('Requires-Dist: mcp; python_version >= "3.10"\n', encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) is None


def test_manifest_search_is_one_level_deep_only(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "package.json").write_text(json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}), encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) is None


def test_ecosystem_is_detected_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text("{}", encoding="utf-8")
    assert detect._ecosystem_of(tmp_path) is Ecosystem.NPM
```

Keep every existing root-level test green.

- [ ] **Step 2: Run — expect the new tests to fail with `None` / `is None` assertions**

- [ ] **Step 3: Implement**

```python
_PY_MANIFESTS = ("pyproject.toml", "requirements.txt", "PKG-INFO")


def _manifest_dirs(root: Path) -> list[Path]:
    """`root` plus its immediate subdirectories. npm tarballs extract to
    `package/`, sdists to `<name>-<version>/`; one level covers both without
    walking into vendored trees."""
    if not root.is_dir():
        return []
    return [root, *sorted(p for p in root.iterdir() if p.is_dir())]


def _pin_from_metadata(metadata: Path) -> str | None:
    """`Requires-Dist:` lines of a wheel METADATA or sdist PKG-INFO."""
    try:
        text = metadata.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Requires-Dist:"):
            pin = _pin_from_requirement(line.partition(":")[2], _PY_SDK_NAMES)
            if pin is not None:
                return pin
    return None
```

In `_pin_from_requirement`, strip an environment marker before anything else: `requirement = requirement.split(";", 1)[0]`.

`detect_sdk_pin`: iterate `_manifest_dirs(root)`; in each, try `pyproject.toml` → `_pin_from_pyproject`, `requirements.txt` → `_pin_from_requirements_txt`, `PKG-INFO` → `_pin_from_metadata`, `package.json` → `_pin_from_package_json`; then `for meta in root.glob("*.dist-info/METADATA")` → `_pin_from_metadata`. First non-`None` wins.

`_ecosystem_of`: PYPI if any manifest dir contains any of `_PY_MANIFESTS` or `root.glob("*.dist-info")` is non-empty; NPM if any manifest dir contains `package.json`; else `None`.

- [ ] **Step 4: Prove it on the two real packages** (passive fetch, already covered by the go-ahead)

```bash
uv run python - <<'EOF'
import httpx, shutil
from agent_perimeter.census import artifacts, detect
from agent_perimeter.model.census import PackageCoords, Ecosystem
for eco, name in [(Ecosystem.NPM, "@modelcontextprotocol/server-filesystem"), (Ecosystem.PYPI, "mcp-server-fetch")]:
    with httpx.Client() as c:
        r = artifacts.fetch_artifact(c, PackageCoords(ecosystem=eco, name=name, version=None))
    fp = detect.detect_features(r.root)
    print(eco.value, fp.sdk_version, fp.is_unknown)
    shutil.rmtree(r.root, ignore_errors=True)
EOF
```
Expected: both print a non-`None` `sdk_version` and `False`. Paste the output into the report.

- [ ] **Step 5: Tests, lint, type-check, commit**

```bash
uv run pytest tests/census -q --no-cov
uv run ruff check agent_perimeter tests && uv run ruff format --check agent_perimeter/census/detect.py tests/census/test_detect.py && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/detect.py tests/census/test_detect.py
git commit -m "fix: find the SDK pin under package/, <name>-<ver>/, PKG-INFO and dist-info METADATA

The first full census classified 94% of artifacts unknown because
detect_sdk_pin only looked at the extraction root; npm and PyPI artifacts
keep their manifests one directory down, and wheels keep requirements in
METADATA. Environment markers no longer masquerade as a version pin.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6 (controller): re-run Task 4** into the same `docs/census/2026-09-14/` directory (nothing has been published from the first run, so overwriting it is not a correction of a published result) and re-verify per Task 4 Step 4.

## Self-review

**Spec coverage.** Decision 5 (full Tier 1, Tier 1+2 only, Tier 3 unwired) → Task 4 uses the default CLI which never calls `tier3`; Task 5's entry states it did not run. CHANGELOG's "when the first real run publishes, its entry states at minimum" list — population with per-ecosystem Tier 2 n, whether Tier 3 ran, tool version + method hash, fetch failures + limitations — every item has a line in Task 5 Step 2. CLAUDE.md "Registry collection" bullet — rate limits and contact URL verified in Task 3 Step 3/4 and Task 2; fetch failures recorded in Task 5. Hard rule 8 — Task 1's digest-only test, Task 3 Step 5, Task 4 Step 4, Task 5 Step 5, and the `run.log` deletion. Definition-of-done report contents (sample, population, method, window, terms, raw data, script) — Task 4 Step 5 checks the rendered report; Task 5 records what was missing rather than hiding it.

**Placeholders.** The `<…>` tokens in Task 5 are values the executor reads off Task 4's output; Step 2 says none may survive. No "TBD"/"handle edge cases" language anywhere.

**Type consistency.** `check(csv_path, summary_path)` in Task 1 matches `analysis/census_analysis.py:144`. CSV header in Task 1 matches `export_raw` at `census_report.py:240-249`. CLI flags `--tier2-n`, `--out`, `--database-url` match `cli.py:261-270` (typer renders `tier2_n` as `--tier2-n`).

**Not in scope, deliberately.** Pushing the 64 unpushed commits (separate go-ahead), the clean-machine verification, and any change to `tier2_n`'s default or the ranking method unless Task 3 Step 4 forces it.
