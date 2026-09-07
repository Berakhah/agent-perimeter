### Task 7: The published census report

**Files:**
- Create: `agent_perimeter/report/census_report.py`
- Create: `agent_perimeter/report/templates/census.html.j2`
- Create: `analysis/census_analysis.py`
- Create: `docs/census/CHANGELOG.md`
- Test: `tests/report/test_census_report.py`

**Interfaces:**
- Produces: `TERM_DEFINITIONS`; `Aggregate(supports, does_not_support, unknown, n)`; `aggregate(records) -> dict[str, Aggregate]`; `render_census(run, records) -> str`; `export_raw(run, records, *, salt: bytes, out: Path) -> Path`.
- Consumes: `CensusRun`, `CensusRecord`, `SELECTION_METHOD`, `method_hash`, Jinja2 environment from Week 3 Task 12.

This is the marketing, and it is also the single largest liability in the project. Every requirement below comes from B9 or brief §8 and none is optional.

**The word "vulnerable" does not appear in this report.** It is the word the existing literature abuses, and an artifact-derived observation cannot support it. The report says *"published artifacts show no support for `2026-07-28`"* — which is what was actually measured.

- [ ] **Step 1: RED — the aggregate-only rule and the term definitions**

Create `tests/report/test_census_report.py`:

```python
import pytest

from agent_perimeter.report.census_report import (
    TERM_DEFINITIONS,
    aggregate,
    export_raw,
    render_census,
)
from tests.report.factories import census_fixture


def test_no_third_party_name_or_url_appears_in_the_report() -> None:
    run, records = census_fixture(names=["acme-mcp-server", "widget-tools"])
    html = render_census(run, records)
    for record in records:
        assert record.package_name not in html
        assert record.registry_id not in html


def test_the_word_vulnerable_is_never_used() -> None:
    run, records = census_fixture()
    assert "vulnerable" not in render_census(run, records).lower()


def test_every_reported_term_is_defined() -> None:
    run, records = census_fixture()
    html = render_census(run, records)
    for term in ("population", "sample", "supports 2026-07-28", "unknown", "conformance gap"):
        assert term in TERM_DEFINITIONS
        assert TERM_DEFINITIONS[term] in html


def test_fetch_failures_appear_even_when_zero() -> None:
    run, records = census_fixture(fetch_failures=0)
    assert "Fetch failures: 0" in render_census(run, records)


def test_unknown_is_reported_separately_and_never_folded_into_a_denominator() -> None:
    run, records = census_fixture(unknown=12)
    agg = aggregate(records)["2026-07-28"]
    assert agg.unknown == 12
    assert agg.n == agg.supports + agg.does_not_support
    assert "12 unknown" in render_census(run, records)


def test_raw_export_is_keyed_by_digest_and_carries_no_names(tmp_path) -> None:
    run, records = census_fixture(names=["acme-mcp-server"])
    path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    body = path.read_text()
    assert "acme-mcp-server" not in body
    assert "coords_digest" in body


def test_the_report_states_the_tool_version_and_method_hash() -> None:
    run, records = census_fixture()
    html = render_census(run, records)
    assert run.method_hash in html and run.tool_version in html
```

Run: `uv run pytest tests/report/test_census_report.py`
Expected: `ImportError: cannot import name 'render_census'`

- [ ] **Step 2: GREEN — terms first, then the renderer**

Create `agent_perimeter/report/census_report.py`:

```python
"""The published census report. Aggregate only. Defines every term it uses."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

TERM_DEFINITIONS: dict[str, str] = {
    "population": (
        "Every entry returned by the official MCP registry API between the collection "
        "window's start and end, including entries whose package coordinates could not "
        "be resolved."
    ),
    "sample": (
        "Tier 1 is the whole population. Tier 2 is the top n by download count within "
        "each ecosystem, selected as described under Method."
    ),
    "supports 2026-07-28": (
        "The package's published artifact pins an MCP SDK at or above the version that "
        "introduced the revision's mandatory methods, and its source contains a handler "
        "for server/discover. This is a statement about a published artifact, not about "
        "any running deployment."
    ),
    "does not support 2026-07-28": (
        "The published artifact pins an SDK below that floor, or contains no such "
        "handler. It does not mean the software is insecure, and it does not mean a "
        "deployment is exposed."
    ),
    "unknown": (
        "Coordinates could not be resolved, the artifact could not be fetched, or the "
        "source could not be parsed. Reported separately and never folded into a "
        "denominator."
    ),
    "conformance gap": (
        "A server that claims a revision and does not exhibit a feature that revision "
        "requires. Measurable only against a live authorised target, so it appears in "
        "scan reports and never in this census."
    ),
}


@dataclass(slots=True, frozen=True)
class Aggregate:
    supports: int
    does_not_support: int
    unknown: int

    @property
    def n(self) -> int:
        """Denominator excludes unknowns. Guessing at an unknown is the thing we sell against."""
        return self.supports + self.does_not_support

    @property
    def share(self) -> float | None:
        return None if self.n == 0 else self.supports / self.n
```

`render_census` passes only aggregates and run metadata into the template. **`CensusRecord` instances never reach the template context** — that is what makes the aggregate-only test hold structurally rather than by review.

- [ ] **Step 3: The template**

Create `agent_perimeter/report/templates/census.html.j2` with, in order: headline finding; collection window with both timestamps; population size; tier-2 `n` and `SELECTION_METHOD`; fetch failures; the per-revision aggregate table with `n` and unknown counts shown beside every percentage; `TERM_DEFINITIONS` as a definition list; tool version and method hash; a link to the raw data and `analysis/census_analysis.py`; the disclosure policy link; and the changelog link.

Reuse `report.css` from Week 3 Task 12 — print-first, greyscale-safe, no colour-only encoding.

- [ ] **Step 4: The analysis script**

Create `analysis/census_analysis.py`: reads the published `records.csv`, recomputes every number in the report, and prints them beside the published figures with a pass/fail per line.

```bash
uv run python analysis/census_analysis.py docs/census/2026-09-01/records.csv
```

Expected: every line reports `match`. This is the reproducibility claim, and it must be runnable by a stranger with the published CSV and nothing else — no database, no salt, no API key.

- [ ] **Step 5: Raw data with the salt withheld**

`export_raw` writes `records.csv` with `coords_digest, ecosystem, sdk_version, supports_2026_07_28, fetch_status, collected_at` — no names, no URLs. The salt is generated once per run, stored **outside the repo**, and published when the 90-day embargo expires, at which point the digests become resolvable and the naming question is moot.

Document this in `docs/security.md` (Task 8) and note it in the report's method section, because an unexplained opaque key looks like obfuscation rather than restraint.

- [ ] **Step 6: The changelog**

Create `docs/census/CHANGELOG.md`:

```markdown
# Census changelog

Results are versioned, never overwritten. Each run gets its own dated directory.

## 2026-09-01 — first publication
- Population: <n> registry entries. Tier 2: <n> per ecosystem.
- Tool version <v>, method hash <h>.
- Fetch failures: <n>. Known limitations: <...>
```

- [ ] **Step 7: Commit**

```bash
uv run pytest tests/report/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/report/census_report.py agent_perimeter/report/templates/census.html.j2 \
        analysis/ docs/census/ tests/report/test_census_report.py
git commit -m "feat: aggregate-only census report with defined terms and raw data export"
```

---

