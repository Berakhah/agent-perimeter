### Task 5: Tier-2 sampling

**Files:**
- Create: `agent_perimeter/census/sample.py`
- Test: `tests/census/test_sample.py`

**Interfaces:**
- Produces: `RankSource` (`StrEnum`: `pypi_recent_downloads`, `npm_last_month_downloads`, `unavailable`); `rank(client, entries) -> list[RankedEntry]`; `top_n(ranked, n) -> list[RankedEntry]`; `SELECTION_METHOD` (a human-readable string embedded in the report).
- Consumes: `RegistryEntry`, `FetchStatus`.

Two honesty constraints shape this module. **Selection must be deterministic** — the same population and the same `n` produce the same sample every time, so a reader re-running the analysis script gets the same tier 2. And **PyPI and npm download counts are not comparable**: different windows, different mirror and CI handling. Tier 2 is therefore ranked *within* each ecosystem and the report says so, rather than merging two incomparable metrics into one leaderboard.

- [ ] **Step 1: RED — determinism, tie-breaks and incomparability**

Create `tests/census/test_sample.py`:

```python
from agent_perimeter.census.sample import RankSource, top_n
from tests.census.factories import ranked


def test_selection_is_deterministic() -> None:
    pop = ranked([("a", 10), ("b", 30), ("c", 30), ("d", 5)])
    assert [e.entry.name for e in top_n(pop, 2)] == [e.entry.name for e in top_n(pop, 2)]


def test_ties_break_on_registry_id_not_arrival_order() -> None:
    pop = ranked([("zeta", 30), ("alpha", 30)])
    assert [e.entry.name for e in top_n(pop, 2)] == ["alpha", "zeta"]


def test_ranking_happens_within_an_ecosystem_never_across() -> None:
    """PyPI and npm counts are different measurements. Merging them is a lie."""
    pop = ranked([("py-a", 100, "pypi"), ("js-a", 5, "npm")])
    selected = top_n(pop, 2)
    assert {e.rank_source for e in selected} == {
        RankSource.PYPI_RECENT_DOWNLOADS,
        RankSource.NPM_LAST_MONTH_DOWNLOADS,
    }


def test_an_entry_with_no_download_metric_is_excluded_and_counted() -> None:
    pop = ranked([("a", 10), ("b", None)])
    selected = top_n(pop, 5)
    assert len(selected) == 1
    assert sum(1 for e in pop if e.rank_source is RankSource.UNAVAILABLE) == 1


def test_n_larger_than_the_population_returns_the_population() -> None:
    assert len(top_n(ranked([("a", 1)]), 200)) == 1
```

Run: `uv run pytest tests/census/test_sample.py`
Expected: `ModuleNotFoundError`

- [ ] **Step 2: GREEN — ranking and selection**

Create `agent_perimeter/census/sample.py`:

```python
"""Tier-2 selection. Deterministic, within-ecosystem, and it states its method."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.model.census import Ecosystem

PYPI_DOWNLOADS = "https://pypistats.org/api/packages/{name}/recent"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month/{name}"

SELECTION_METHOD = (
    "Tier 2 is the top n packages by download count within each ecosystem, ranked "
    "separately because PyPI recent downloads and npm last-month downloads are "
    "different measurements over different windows and are not comparable. Ties "
    "break on registry id ascending. Entries with no available download metric are "
    "excluded from tier 2 and counted in the report."
)


class RankSource(StrEnum):
    PYPI_RECENT_DOWNLOADS = "pypi_recent_downloads"
    NPM_LAST_MONTH_DOWNLOADS = "npm_last_month_downloads"
    UNAVAILABLE = "unavailable"


@dataclass(slots=True, frozen=True)
class RankedEntry:
    entry: RegistryEntry
    downloads: int | None
    rank_source: RankSource


def top_n(ranked: list[RankedEntry], n: int) -> list[RankedEntry]:
    """Top n per ecosystem, deterministic. n is per ecosystem, not overall."""
    out: list[RankedEntry] = []
    for eco in Ecosystem:
        pool = [
            r
            for r in ranked
            if r.entry.coords is not None
            and r.entry.coords.ecosystem is eco
            and r.downloads is not None
        ]
        pool.sort(key=lambda r: (-(r.downloads or 0), r.entry.registry_id))
        out.extend(pool[:n])
    return out
```

- [ ] **Step 3: Verify the descope lever actually works**

```bash
uv run python -c "
from agent_perimeter.census.sample import top_n
from tests.census.factories import ranked
pop = ranked([(f'p{i}', 1000 - i) for i in range(300)])
print(len(top_n(pop, 200)), len(top_n(pop, 50)))
"
```

Expected: `200 50`. The lever is a parameter, not a rewrite — which is what makes it usable on day 24 under pressure.

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/sample.py tests/census/
git commit -m "feat: deterministic within-ecosystem tier-2 sampling"
```

---

