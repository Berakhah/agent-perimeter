### Task 1: Census schema and migration

**Files:**
- Create: `agent_perimeter/model/census.py`
- Modify: `agent_perimeter/db/models.py`
- Create: `alembic/versions/0004_census.py`
- Test: `tests/db/test_census_schema.py`

**Interfaces:**
- Produces: `Ecosystem`; `FetchStatus` (`StrEnum`: `ok`, `not_found`, `throttled`, `timeout`, `parse_error`, `unsupported_coords`, `too_large`); `PackageCoords(ecosystem, name, version)`; `CensusRun`; `CensusRecord`.
- Consumes: `FeatureSet`, `Derivation` (Week 1 Task 7), `Base` (Week 2 Task 4).

Three columns carry weight beyond storage. `census_run.fetch_failures` exists because B10 warns that throttling silently invalidates a sample — as a column, the report cannot omit it. `census_run.method_hash` binds every published number to the exact collection method that produced it, satisfying B9 mechanically rather than by discipline. `census_record.coords_digest` is what lets raw data be published without naming anyone.

- [ ] **Step 1: RED — write the schema test**

Create `tests/db/test_census_schema.py`:

```python
from agent_perimeter.db.models import CensusRecord, CensusRun


def test_census_run_records_failures_and_method() -> None:
    cols = {c.name for c in CensusRun.__table__.columns}
    assert {"population_size", "fetch_failures", "tool_version", "method_hash"} <= cols


def test_census_record_has_no_column_that_could_hold_a_secret() -> None:
    forbidden = {"token", "secret", "password", "api_key", "credential"}
    for col in CensusRecord.__table__.columns:
        assert not any(f in col.name.lower() for f in forbidden)


def test_coords_digest_is_not_nullable() -> None:
    assert CensusRecord.__table__.c.coords_digest.nullable is False
```

Run: `uv run pytest tests/db/test_census_schema.py`
Expected: `ImportError: cannot import name 'CensusRun'`

- [ ] **Step 2: GREEN — the domain model**

Create `agent_perimeter/model/census.py`:

```python
"""Census domain types. Nothing here talks to a third-party MCP server."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Ecosystem(StrEnum):
    PYPI = "pypi"
    NPM = "npm"


class FetchStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    THROTTLED = "throttled"
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"
    UNSUPPORTED_COORDS = "unsupported_coords"
    TOO_LARGE = "too_large"

    @property
    def is_failure(self) -> bool:
        return self is not FetchStatus.OK


class PackageCoords(BaseModel):
    model_config = ConfigDict(frozen=True)

    ecosystem: Ecosystem
    name: str
    version: str | None = None

    def digest(self, salt: bytes) -> str:
        """Stable pseudonym. Published raw data is keyed by this, never by name.

        The salt is withheld for the embargo period (docs/security.md), which is
        what lets per-record measurements ship on day one without naming anyone.
        """
        payload = f"{self.ecosystem.value}:{self.name.lower()}".encode()
        return hashlib.blake2b(payload, key=salt, digest_size=16).hexdigest()
```

Append to `agent_perimeter/db/models.py`:

```python
class CensusRun(Base):
    __tablename__ = "census_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    population_size: Mapped[int]
    fetch_failures: Mapped[int] = mapped_column(default=0)
    tool_version: Mapped[str]
    method_hash: Mapped[str]
    tier2_n: Mapped[int | None]
    registry_endpoint: Mapped[str]


class CensusRecord(Base):
    __tablename__ = "census_record"

    id: Mapped[int] = mapped_column(primary_key=True)
    census_run_id: Mapped[int] = mapped_column(ForeignKey("census_run.id"))
    registry_id: Mapped[str]
    coords_digest: Mapped[str] = mapped_column(nullable=False, index=True)
    ecosystem: Mapped[str | None]
    package_name: Mapped[str | None]
    sdk_version: Mapped[str | None]
    feature_set_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fetch_status: Mapped[str]
    fetch_detail: Mapped[str | None]
    rank_metric: Mapped[int | None]
    rank_metric_source: Mapped[str | None]
    collected_at: Mapped[datetime]
```

`package_name` is stored locally so a re-run resolves coordinates without re-paginating. It is **never** exported — Task 7 has a test proving that.

- [ ] **Step 3: Migration**

```bash
uv run alembic revision --autogenerate -m "census tables"
uv run alembic upgrade head && uv run alembic downgrade -1 && uv run alembic upgrade head
```

Expected: round-trips cleanly. Rename the generated file to `0004_census.py`.

- [ ] **Step 4: Commit**

```bash
uv run ruff check . && uv run mypy --strict agent_perimeter && uv run pytest tests/db/
git add agent_perimeter/model/census.py agent_perimeter/db/models.py alembic/ tests/db/
git commit -m "feat: census schema with fetch-failure and method-hash columns"
```

---

