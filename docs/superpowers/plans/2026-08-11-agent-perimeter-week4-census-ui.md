# Agent Perimeter — Week 4: Census, UI and Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure what fraction of the public MCP ecosystem can support `2026-07-28` one month after it shipped, publish that with a methodology a hostile reader cannot dismantle, ship the five remaining UI screens, and prove the whole thing reproduces on a clean machine.

**Architecture:** The census touches no third-party server. It reads the registry API and published package artifacts only, derives a `FeatureSet` with `derived_from = ARTIFACT` at a confidence strictly below any live probe, and reports two populations separately. The report is rendered by `report/census_report.py` as a static artifact, deliberately not by the Next.js app, so a UI slip cannot block publication.

**Tech Stack:** Python 3.12+, `uv`, `ruff`, `mypy --strict`, `pytest`, `hypothesis`, Pydantic v2, SQLAlchemy 2 + alembic, httpx, Jinja2, FastAPI. Web: Next.js 15 (App Router), TypeScript strict, Tailwind v4, Playwright, axe-core.

**Spec:** `docs/superpowers/specs/2026-08-11-agent-perimeter-design.md`
**Revision (binding):** `docs/superpowers/specs/2026-08-29-agent-perimeter-plan-revision.md` — **read it first.** Where it and this plan disagree, the revision wins.

> **Blocking corrections to this week, summarised.** Everything below was verified against the live registry API on 29 August 2026.
> - **Task 2 — the census stops at 100 servers and reports it as complete.** The plan reads `metadata["next_cursor"]`; the live field is **`nextCursor`**. `.get("next_cursor")` returns `None` on page one, the loop logs "exhausted after 1 pages", and `population_is_complete` is `True`. That publishes a census of 100 of 4,000+ servers **asserting completeness** — the exact failure this product exists to reject, in the artifact that is the marketing. Add a loud guard against single-page termination. Revision §1.4.
> - **Task 2 — use `?version=latest` and de-duplicate on `name`.** 33 % of unfiltered rows are older versions of the same server (100 rows → 67 unique names), so the population inflates by roughly half. The filter is supported and verified.
> - **Task 2 — ~70 % of the registry has no artifact.** In a 100-row sample, 71 entries carry only `remotes` and 30 carry `packages` (29 npm : 1 pypi). Add a `remotes` field to `RegistryEntry` and a `distribution` column to `census_record` (`package_npm | package_pypi | package_other | remote_only | none`). `registryType` also takes `oci`/`nuget`/`mcpb`, which `_coords` currently merges into "no coordinates".
> - **Task 5 — the registry exposes no download counts at all** (verified: no `downloads`, `stars`, `install_count` or popularity field in any row). Tier-2 ranking must come from `pypistats.org` and `api.npmjs.org`, which is what the plan does — but say so in `SELECTION_METHOD`, and record that the registry itself offers no popularity signal.
> - **Task 7 — the headline claim is not supportable from artifacts alone.** "What fraction of the public MCP ecosystem" cannot be answered from artifacts for ~70 % of servers. **Decided 29 August 2026:** report it as a **two-stratum estimate** — artifact-derived for the npm/PyPI stratum, `server/discover`-derived for a sample of `remote_only` — with both `n`s, both methods and both intervals shown separately and **never pooled into one unqualified number**. Revision §1.5.
> - **New task — Tier 3, the remote-stratum sample.** Seeded random n = 100 from the `remote_only` stratum; **one unauthenticated `server/discover` per host and nothing else** — no `initialize`, no `tools/list`, no fallback, no retry; a non-answer is recorded as `unreachable` and that host is never contacted again, including on a re-run. Confined to `agent_perimeter/census/tier3.py`. Honour `robots.txt`, rate-limit, contact URL in `User-Agent`, opt-out list checked before every request. `derived_from = LIVE_DISCOVER`; observe-or-abstain applies unchanged. Publish the seed and the frame snapshot; publish `docs/security.md` describing the traffic **before the first request goes out**. Revision §1.5.
> - **Task 4 — the SDK-pin inference is unvalidated and may be inverted.** Most packages declare a *range*, not a pin, so a lower bound says nothing about the runtime SDK. **Add a ground-truth task:** install n = 30 fetchable packages into the Week-1 container, live-fingerprint them, and publish the agreement rate as the basis for `ARTIFACT_CONFIDENCE`. Running your own copy of a public package in your own sandbox is not third-party probing. Distinguish *pin* / *floor* / *unconstrained*, and treat unconstrained as `unknown`. Revision §1.6.
> - **New task — real-world precision.** Take a random n = 100 from the census population, run the deterministic suite over their tool metadata, and **manually adjudicate every firing** as TP or FP. Publish precision from that real population, separately from fixture-corpus recall, with the adjudication log. This is the highest-leverage change in the revision: it converts differentiator (c) from a self-graded exam into the most defensible artifact in the category, and it is the only way the revision §3 false-positive modes surface before a customer finds them. Revision §4.2.
> - **Task 17 — no Docker socket in any compose file.** A container holding `/var/run/docker.sock` is host root, and that container parses untrusted JSON-RPC. `POST /api/scans` with a stdio target returns a clear refusal directing the user to the CLI. Revision §1.7.
> - **Task 3 — use `tarfile.extractall(filter="data")`** (Python 3.12) rather than the hand-rolled member walk: it rejects traversal, symlinks, **hardlinks**, devices and setuid bits, and is maintained upstream. Keep the size caps; add a per-file cap. `test_the_module_never_executes_an_artifact` greps for strings — keep it, but assert the `data` filter, which is the thing that actually matters. Revision §5.7.
> - **Cloning untrusted repos runs on the host.** `git clone` of a hostile repository is a code-execution surface, and `git log -p --all` with `capture_output=True` buffers a whole repository in memory. Clone with `--no-checkout --filter=blob:none`, `core.hooksPath=/dev/null`, templates disabled, **inside the Week-1 container**; stream the log output. B3's reasoning applies here with equal force. Revision §5.4.
> - **Task 6 — `test_passive_only` walks the import graph one level deep,** while claiming "can never reach". Make it transitive.
> - **Task 5 — `n` is per ecosystem, so `tier2_n=200` yields up to 400.** Given the ~29:1 npm:PyPI split, the PyPI "top 200" is effectively a census of PyPI. Report each ecosystem's `n` and population separately.

**Prerequisite:** Week 3 completion gate passed — 33 checks registered (25 from Week 2's revised gate, 4 `active/`, 2 `injection/`, 2 `policy/`), capability graph rendering with per-edge derivation, `docs/methodology.md` carrying a per-check precision/recall table regenerated in CI.

## Global Constraints

Carried verbatim from Weeks 1–3. Every task's requirements implicitly include these.

- **Python 3.12+**, `uv`, `ruff` lint+format, **`mypy --strict`** on every module.
- **Licence Apache-2.0.** Dependencies MIT / Apache-2.0 / BSD / OFL only.
- **No secrets in the repo, ever — including fixtures.** `gitleaks` blocks commits.
- **$0 recurring cost.** **Coverage floor 75%.** **TDD, no exceptions.**
- **No active probe without a scope file.** Fails closed. Enforced by the registry and re-asserted per check.
- **No exploit weaponisation.** A probe proves reachability and stops.
- **Never validate a discovered secret against a live service.**
- **Every finding cites a CWE and a resolvable taxonomy entry.**
- **Copy rule:** errors state what happened and what to do, without apologising.
- **Repo stays private until first release** — which is the last task of this week.

## Constraints specific to this week

- **Public-registry scanning is passive only. [REVISED 29 Aug 2026]** Tiers 1–2 may fetch the registry API and published package artifacts, and nothing else. **Tier 3 may send exactly one unauthenticated `server/discover` per sampled host, and nothing else** — never `initialize`, never `tools/list`, never a tool invocation, never a retry. Task 6 enforces both structurally rather than by convention: the literal host allowlist for every census module except `agent_perimeter/census/tier3.py`, and for `tier3.py` an assertion that it contains exactly one JSON-RPC method string (`server/discover`) and no host literal at all. Revision §1.5.
- **Aggregate statistics only in the published report.** No third-party server named, reply or no reply. Task 7 enforces this with a test over the rendered output.
- **Downloaded artifacts are never executed.** Not `setup.py`, not `npm install`, not an import. Extraction is guarded against path traversal, symlinks and decompression bombs.
- **Secrets found during the census bypass the embargo clock entirely** — notify owner and platform immediately, never publish, never validate.

## Week 4 deliverable

A published census report with sample, population, method, collection window, term definitions, raw data and analysis script; a coordinated-disclosure policy; six working screens that pass axe, work keyboard-only and print correctly; and a clean-machine `docker compose up`.

**Closes DoD 7, 8, 9 and 10** — and with them all ten.

## Descope lever, decided in advance

Per spec §12, in order:

1. Tier 2 `n` scales from 200 down to 50. Both populations are reported separately, so no published claim weakens — only the tier-2 interval widens, and the report states `n` either way.
2. If the week slips past day 24, the UI reduces to the report view (already built in Week 3) plus the capability graph, which is what DoD 5 and DoD 9 actually require. Screens 1, 2 and 5 become v1.1.

Tier 1 — the full census by cheap API pagination — carries the headline finding and is **never** the thing that gets cut.

---

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

### Task 2: Registry pagination

**Files:**
- Create: `agent_perimeter/census/__init__.py`
- Create: `agent_perimeter/census/fetch.py`
- Test: `tests/census/__init__.py`
- Test: `tests/census/test_fetch.py`
- Test fixture: `tests/fixtures/registry/page1.json`, `page2.json`

**Interfaces:**
- Produces: `USER_AGENT`; `Outcome`; `FetchLog`; `RegistryEntry(registry_id, name, coords, repository_url)`; `paginate(client, endpoint, log) -> Iterator[RegistryEntry]`.
- Consumes: `PackageCoords`, `FetchStatus`, `Ecosystem`.

**Every test in this file runs against recorded fixtures.** No test in this repo makes a live network call — a suite that depends on a third party's uptime fails for reasons unrelated to the code.

- [ ] **Step 1: RED — pagination and throttle accounting**

Create `tests/census/test_fetch.py`:

```python
import httpx

from agent_perimeter.census.fetch import USER_AGENT, FetchLog, paginate
from agent_perimeter.model.census import FetchStatus


def _transport(pages: list[dict]) -> httpx.MockTransport:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        i = calls["n"]
        calls["n"] += 1
        return httpx.Response(200, json=pages[min(i, len(pages) - 1)])

    return httpx.MockTransport(handler)


def test_paginate_follows_the_cursor_to_exhaustion(registry_pages: list[dict]) -> None:
    client = httpx.Client(transport=_transport(registry_pages))
    entries = list(paginate(client, "https://example.invalid/v0/servers", FetchLog()))
    assert len(entries) == 3
    assert entries[0].registry_id


def test_user_agent_identifies_the_tool_and_a_contact_url() -> None:
    assert "agent-perimeter" in USER_AGENT
    assert "https://" in USER_AGENT


def test_a_throttled_page_is_recorded_not_swallowed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    log = FetchLog()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    list(paginate(client, "https://example.invalid/v0/servers", log, max_retries=1))
    assert log.failures == 1
    assert log.outcomes[0].status is FetchStatus.THROTTLED


def test_a_partial_population_is_never_reported_as_complete() -> None:
    log = FetchLog()
    log.record(FetchStatus.THROTTLED, "page 4")
    assert log.population_is_complete is False
```

Run: `uv run pytest tests/census/test_fetch.py`
Expected: `ModuleNotFoundError: agent_perimeter.census`

- [ ] **Step 2: GREEN — the fetcher**

Create `agent_perimeter/census/fetch.py`:

```python
"""Registry pagination. Read-only, rate-limited, and it identifies itself."""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field

import httpx
from pydantic import BaseModel, ConfigDict

from agent_perimeter import __version__
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords

USER_AGENT = (
    f"agent-perimeter/{__version__} "
    "(+https://github.com/OWNER/agent-perimeter/blob/main/docs/security.md)"
)

# ponytail: fixed interval rather than a token bucket. One request every 500ms sits
# well inside any published registry limit; swap for a bucket if one is ever hit.
MIN_INTERVAL_S = 0.5


@dataclass(slots=True)
class Outcome:
    status: FetchStatus
    detail: str


@dataclass(slots=True)
class FetchLog:
    outcomes: list[Outcome] = field(default_factory=list)

    def record(self, status: FetchStatus, detail: str) -> None:
        self.outcomes.append(Outcome(status, detail))

    @property
    def failures(self) -> int:
        return sum(1 for o in self.outcomes if o.status.is_failure)

    @property
    def population_is_complete(self) -> bool:
        """False if any page failed. A sample with an unknown hole is not a census."""
        return self.failures == 0


class RegistryEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    registry_id: str
    name: str
    coords: PackageCoords | None
    repository_url: str | None


def _coords(package: dict[str, object]) -> PackageCoords | None:
    registry = str(package.get("registryType") or package.get("registry_name") or "")
    name = package.get("identifier") or package.get("name")
    if not isinstance(name, str):
        return None
    match registry.lower():
        case "pypi":
            eco = Ecosystem.PYPI
        case "npm":
            eco = Ecosystem.NPM
        case _:
            return None
    version = package.get("version")
    return PackageCoords(
        ecosystem=eco, name=name, version=version if isinstance(version, str) else None
    )


def paginate(
    client: httpx.Client,
    endpoint: str,
    log: FetchLog,
    *,
    max_retries: int = 3,
) -> Iterator[RegistryEntry]:
    cursor: str | None = None
    page = 0
    while True:
        page += 1
        params: dict[str, object] = {"limit": 100} | ({"cursor": cursor} if cursor else {})
        body = _get_page(client, endpoint, params, log, page, max_retries)
        if body is None:
            return
        for server in body.get("servers", []):
            entry = _entry(server)
            if entry is not None:
                yield entry
        cursor = (body.get("metadata") or {}).get("next_cursor")
        if not cursor:
            log.record(FetchStatus.OK, f"exhausted after {page} pages")
            return
        time.sleep(MIN_INTERVAL_S)
```

`_get_page` retries on 429 honouring `Retry-After`, records `THROTTLED` / `TIMEOUT` / `PARSE_ERROR` on give-up, and returns `None`. `_entry` maps a registry record to `RegistryEntry`, taking the first supported package coordinate.

- [ ] **Step 3: Confirm the endpoint against reality, and write down what you saw**

The registry API's base URL and pagination envelope must be confirmed at implementation time, not assumed from this plan. Being checkable is the entire product; a census built on a guessed endpoint is the exact failure this project exists to avoid.

```bash
curl -sS -A "$(uv run python -c 'from agent_perimeter.census.fetch import USER_AGENT; print(USER_AGENT)')" \
  'https://registry.modelcontextprotocol.io/v0/servers?limit=2' | head -c 2000
```

Record in `docs/methodology.md` under a new `## Census collection` heading: the exact endpoint, the pagination field names observed, the date, and the response envelope. Update `tests/fixtures/registry/page*.json` to match what came back. If the endpoint differs from the one above, the fixtures and `paginate` change and this plan is wrong — the recorded observation wins.

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/ tests/census/ tests/fixtures/registry/ docs/methodology.md
git commit -m "feat: rate-limited registry pagination with explicit failure accounting"
```

---

### Task 3: Artifact fetch and safe extraction

**Files:**
- Create: `agent_perimeter/census/artifacts.py`
- Test: `tests/census/test_artifacts.py`

**Interfaces:**
- Produces: `ArchiveRejected`; `ArtifactResult(status, detail, root, version)`; `safe_extract(archive, dest) -> list[Path]`; `fetch_artifact(client, coords) -> ArtifactResult`; `MAX_ARCHIVE_BYTES`, `MAX_UNCOMPRESSED_BYTES`, `MAX_MEMBERS`.
- Consumes: `PackageCoords`, `FetchStatus`.

An sdist or npm tarball is attacker-controlled input from an untrusted party. It is downloaded to a temporary directory, size-capped, extracted with traversal and symlink rejection, read, and deleted. **It is never executed** — no `setup.py`, no `npm install`, no import.

- [ ] **Step 1: RED — the extraction guards**

Create `tests/census/test_artifacts.py`:

```python
import io
import tarfile
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from agent_perimeter.census.artifacts import MAX_MEMBERS, ArchiveRejected, safe_extract


def _tar_with(tmp_path: Path, name: str, *, symlink_to: str | None = None) -> Path:
    path = tmp_path / "archive.tar.gz"
    with tarfile.open(path, mode="w:gz") as tf:
        info = tarfile.TarInfo(name)
        if symlink_to:
            info.type = tarfile.SYMTYPE
            info.linkname = symlink_to
            tf.addfile(info)
        else:
            data = b"x"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


@pytest.mark.parametrize("name", ["../escape.py", "/etc/passwd", "a/../../escape.py"])
def test_traversal_members_are_rejected(tmp_path: Path, name: str) -> None:
    archive = _tar_with(tmp_path, name)
    with pytest.raises(ArchiveRejected, match="outside"):
        safe_extract(archive, tmp_path / "out")


def test_symlink_members_are_rejected(tmp_path: Path) -> None:
    archive = _tar_with(tmp_path, "link", symlink_to="/etc/passwd")
    with pytest.raises(ArchiveRejected, match="symlink"):
        safe_extract(archive, tmp_path / "out")


def test_member_count_is_capped() -> None:
    assert MAX_MEMBERS <= 20_000


@given(st.text(min_size=1, max_size=40))
def test_no_member_name_ever_escapes_the_destination(name: str) -> None:
    """Property: whatever the member is called, nothing lands outside dest."""
    from agent_perimeter.census.artifacts import _resolve_member

    dest = Path("/tmp/ap-extract").resolve()
    resolved = _resolve_member(dest, name)
    assert resolved is None or dest in resolved.parents


def test_the_module_never_executes_an_artifact() -> None:
    src = Path("agent_perimeter/census/artifacts.py").read_text()
    for forbidden in ("subprocess", "os.system", "exec(", "eval(", "importlib"):
        assert forbidden not in src
```

Run: `uv run pytest tests/census/test_artifacts.py`
Expected: `ModuleNotFoundError`

- [ ] **Step 2: GREEN — download and extract**

Create `agent_perimeter/census/artifacts.py`:

```python
"""Download and read published package artifacts. Never execute one."""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from agent_perimeter.model.census import FetchStatus

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 20_000

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
NPM_JSON = "https://registry.npmjs.org/{name}"


class ArchiveRejected(Exception):
    """The archive did something an honest archive does not do."""


@dataclass(slots=True)
class ArtifactResult:
    status: FetchStatus
    detail: str
    root: Path | None
    version: str | None


def _resolve_member(dest: Path, name: str) -> Path | None:
    """Where this member would land, or None if the name is unusable."""
    if not name or name.startswith("/") or "\x00" in name:
        return None
    return (dest / name).resolve()


def safe_extract(archive: Path, dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()
    written: list[Path] = []
    total = 0

    with _open_archive(archive) as bundle:
        members = _members(bundle)
        if len(members) > MAX_MEMBERS:
            raise ArchiveRejected(f"{len(members)} members exceeds {MAX_MEMBERS}")
        for member in members:
            name, size, is_link = _describe(member)
            if is_link:
                raise ArchiveRejected(f"symlink member: {name}")
            target = _resolve_member(resolved_dest, name)
            if target is None or resolved_dest not in target.parents:
                raise ArchiveRejected(f"member resolves outside destination: {name}")
            total += size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ArchiveRejected("uncompressed size cap exceeded")
            _write(bundle, member, target)
            written.append(target)
    return written
```

`fetch_artifact` resolves coordinates through `PYPI_JSON` / `NPM_JSON`, picks the sdist (PyPI) or `dist.tarball` (npm), streams it with a byte cap, and returns `TOO_LARGE`, `NOT_FOUND`, `THROTTLED` or `OK` — never raising into the run loop, because one unfetchable package must not end a census of thousands.

- [ ] **Step 3: REFACTOR — one honest note**

Add above `safe_extract`:

```python
# ponytail: extraction into a temp dir with caps and traversal rejection, not a
# sandboxed container. Justified because nothing here is executed and every file is
# opened read-only; upgrade to the Week 1 container launcher if that ever changes.
```

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/artifacts.py tests/census/test_artifacts.py
git commit -m "feat: artifact fetch with traversal, symlink and bomb guards"
```

---

### Task 4: Feature detection from artifacts

**Files:**
- Create: `agent_perimeter/census/detect.py`
- Modify: `agent_perimeter/transport/revision.py` (add `LIVE_PROBE_CONFIDENCE`)
- Test: `tests/census/test_detect.py`
- Test fixture: `tests/fixtures/artifacts/py_new/`, `tests/fixtures/artifacts/py_old/`, `tests/fixtures/artifacts/js_new/`, `tests/fixtures/artifacts/empty/`

**Interfaces:**
- Produces: `ARTIFACT_CONFIDENCE`; `SDK_FLOOR` (SDK version at which each `Feature` became available); `ArtifactFingerprint(features, sdk_version, claim)`; `detect_sdk_pin(root) -> str | None`; `detect_features(root) -> ArtifactFingerprint`.
- Consumes: `Feature`, `FeatureSet` (= `frozenset[Feature]`, Week 1 Task 7); `Claim`, `Method`, `Derivation` (Week 1 Task 2 `_contracts.py`); `Fingerprint` (Week 1 Task 8).

**Shape note:** Week 1 made `FeatureSet` a plain `frozenset[Feature]` and put provenance on the `Claim`, not on the feature set. This task follows that, returning an `ArtifactFingerprint` that mirrors Week 1's `Fingerprint` — same two fields plus the SDK pin — so the live path and the artifact path stay structurally parallel and the report can compare them without a translation layer.

This is the module the headline claim rests on. Two independent signals must agree before a feature is asserted: the **pinned SDK version** (a package pinned to an SDK predating `2026-07-28` cannot serve that revision, regardless of what its source says) and a **source scan** for the handlers the revision requires. Where the two disagree, the lower wins and a caveat is attached — a claim that hedges is worth more than a claim that is wrong.

Detection is by `ast` parse for Python and a token scan for JavaScript. **No import, no execution, no `eval`.**

- [ ] **Step 1: RED — the confidence ordering and the disagreement rule**

Create `tests/census/test_detect.py`:

```python
from pathlib import Path

from agent_perimeter._contracts import Derivation
from agent_perimeter.census.detect import (
    ARTIFACT_CONFIDENCE,
    detect_features,
    detect_sdk_pin,
)
from agent_perimeter.model.feature import Feature
from agent_perimeter.transport.revision import LIVE_PROBE_CONFIDENCE

FIXTURES = Path("tests/fixtures/artifacts")


def test_artifact_confidence_is_strictly_below_a_live_probe() -> None:
    """An artifact says what a package could do, not what a deployment does."""
    assert ARTIFACT_CONFIDENCE < LIVE_PROBE_CONFIDENCE


def test_a_modern_sdk_pin_is_read_from_pyproject() -> None:
    assert detect_sdk_pin(FIXTURES / "py_new") == "2.1.0"


def test_an_old_sdk_pin_bounds_the_feature_set_regardless_of_source() -> None:
    """Source mentioning server/discover cannot raise a package pinned below it."""
    fp = detect_features(FIXTURES / "py_old")
    assert Feature.SERVER_DISCOVER not in fp.features
    assert "sdk pin" in (fp.claim.caveat or "")


def test_every_artifact_derived_claim_is_marked_as_such() -> None:
    fp = detect_features(FIXTURES / "py_new")
    assert fp.claim.derivation is Derivation.ARTIFACT
    assert fp.claim.confidence == ARTIFACT_CONFIDENCE


def test_unresolvable_coordinates_yield_unknown_not_absent() -> None:
    """No SDK pin and no parseable source is UNKNOWN, never 'does not support'."""
    fp = detect_features(FIXTURES / "empty")
    assert fp.is_unknown
    assert fp.features == frozenset()
    assert fp.claim.caveat


def test_the_features_type_matches_the_live_path() -> None:
    """Same type as transport.revision.Fingerprint.features, so they compare directly."""
    fp = detect_features(FIXTURES / "py_new")
    assert isinstance(fp.features, frozenset)


def test_detection_never_imports_the_artifact() -> None:
    src = Path("agent_perimeter/census/detect.py").read_text()
    for forbidden in ("importlib", "exec(", "eval(", "subprocess", "__import__"):
        assert forbidden not in src
```

Run: `uv run pytest tests/census/test_detect.py`
Expected: `ModuleNotFoundError: agent_perimeter.census.detect`

- [ ] **Step 2: GREEN — the detector**

Create `agent_perimeter/census/detect.py`:

First add the constant the ordering test compares against, to `agent_perimeter/transport/revision.py`:

```python
# A live probe observed the running server answer. It is the strongest evidence
# this tool produces, and every other derivation is calibrated below it.
LIVE_PROBE_CONFIDENCE = 0.95
```

Then create `agent_perimeter/census/detect.py`:

```python
"""Derive a FeatureSet from a published artifact. Parse only; never execute."""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packaging.version import InvalidVersion, Version

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.feature import Feature, FeatureSet

# Strictly below transport.revision.LIVE_PROBE_CONFIDENCE. An artifact tells you
# what a package could do, not what a deployment does.
ARTIFACT_CONFIDENCE = 0.6

# Lowest SDK release that can serve each feature. Below the floor, source evidence
# is discarded: a package cannot serve what its pinned dependency cannot express.
SDK_FLOOR: dict[Feature, dict[str, str]] = {
    Feature.SERVER_DISCOVER: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.RESULT_TYPE: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.CACHEABLE_RESULT: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.MRTR: {"pypi": "2.0.0", "npm": "2.0.0"},
}

SOURCE_SIGNALS: dict[Feature, re.Pattern[str]] = {
    Feature.SERVER_DISCOVER: re.compile(r"""["']server/discover["']"""),
    Feature.RESULT_TYPE: re.compile(r"\bresultType\b|\bresult_type\b"),
    Feature.CACHEABLE_RESULT: re.compile(r"\bttlMs\b|\bcacheScope\b|\bcache_scope\b"),
    Feature.MRTR: re.compile(r"\bInputRequiredResult\b|\binputResponses\b"),
    Feature.X_MCP_HEADER: re.compile(r"\bx-mcp-header\b", re.I),
}

_PY_SDK_NAMES = {"mcp", "modelcontextprotocol"}
_JS_SDK_NAMES = {"@modelcontextprotocol/sdk"}


@dataclass(slots=True, frozen=True)
class ArtifactFingerprint:
    """Mirrors transport.revision.Fingerprint. Same features type, weaker claim."""

    features: FeatureSet
    sdk_version: str | None
    claim: Claim

    @property
    def is_unknown(self) -> bool:
        return not self.features and self.sdk_version is None


def detect_sdk_pin(root: Path) -> str | None:
    """Pinned MCP SDK version, from pyproject / requirements / package.json."""
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
        deps = (data.get("project") or {}).get("dependencies") or []
        for dep in deps:
            if (pin := _pin_from_requirement(str(dep), _PY_SDK_NAMES)) is not None:
                return pin
    ...  # requirements.txt, then package.json dependencies
    return None


def _source_features(root: Path) -> set[Feature]:
    found: set[Feature] = set()
    for path in _source_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            try:
                ast.parse(text)  # parse-only: proves it is source, never runs it
            except SyntaxError:
                continue
        for feature, pattern in SOURCE_SIGNALS.items():
            if pattern.search(text):
                found.add(feature)
    return found


def _claim(value: object, caveat: str | None) -> Claim:
    return Claim(
        value=value,
        method=Method.DETERMINISTIC,
        derivation=Derivation.ARTIFACT,
        confidence=ARTIFACT_CONFIDENCE,
        observed_at=datetime.now(UTC),
        caveat=caveat,
    )


def detect_features(root: Path) -> ArtifactFingerprint:
    pin = detect_sdk_pin(root)
    observed = _source_features(root)
    if pin is None and not observed:
        return ArtifactFingerprint(
            features=frozenset(),
            sdk_version=None,
            claim=_claim(None, "no SDK pin and no parseable source in the published artifact"),
        )

    bounded, dropped = _apply_sdk_floor(observed, pin, root)
    caveat = None
    if dropped:
        names = ", ".join(sorted(f.value for f in dropped))
        caveat = f"source mentions {names} but the sdk pin ({pin}) predates it; sdk pin wins"
    features = frozenset(bounded)
    return ArtifactFingerprint(
        features=features,
        sdk_version=pin,
        claim=_claim(sorted(f.value for f in features), caveat),
    )
```

- [ ] **Step 3: REFACTOR — record the floor's basis, not just its value**

`SDK_FLOOR` is a claim about someone else's release history. Add above it:

```python
# Verified against the SDK changelogs on the collection date and recorded in
# docs/methodology.md under "SDK version floors". If a floor is wrong, every
# artifact-derived number moves — so it is cited, not assumed.
```

Then add the `## SDK version floors` table to `docs/methodology.md`: feature, ecosystem, floor version, release date, changelog URL, date checked.

- [ ] **Step 4: Verify against the fixtures**

Run: `uv run pytest tests/census/ -v`
Expected: all pass, including the disagreement rule and the unknown case.

- [ ] **Step 5: Commit**

```bash
uv run ruff check . && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/detect.py agent_perimeter/transport/revision.py \
        tests/census/ tests/fixtures/artifacts/ docs/methodology.md
git commit -m "feat: artifact feature detection bounded by the pinned SDK version"
```

---

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

### Task 6: Census run pipeline, CLI command, and the passive-only guarantee

**Files:**
- Create: `agent_perimeter/census/run.py`
- Modify: `agent_perimeter/cli.py`
- Test: `tests/census/test_run.py`
- Test: `tests/census/test_passive_only.py`

**Interfaces:**
- Produces: `method_hash() -> str`; `run_census(session, client, *, endpoint, tier2_n) -> CensusRun`; CLI `agent-perimeter census`.
- Consumes: `paginate`, `fetch_artifact`, `detect_features`, `top_n`, `CensusRun`, `CensusRecord`.

**This task's most important artifact is a test, not a feature.** "Public-registry scanning is passive only" is a hard constraint from `CLAUDE.md`; a comment saying so is worth nothing. `test_passive_only.py` walks the import graph of `agent_perimeter.census` with `ast` and fails if any transport or active-check module is reachable from it. The guarantee then survives a future contributor who has not read this plan.

- [ ] **Step 1: RED — the structural guarantee**

Create `tests/census/test_passive_only.py`:

```python
import ast
import re
from pathlib import Path

FORBIDDEN_PREFIXES = (
    "agent_perimeter.transport",
    "agent_perimeter.checks.active",
    "agent_perimeter.checks.injection",
    "agent_perimeter.discover",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_census_can_never_reach_a_transport_or_an_active_check() -> None:
    """The census must be structurally incapable of touching a third-party server."""
    offences: list[str] = []
    for path in Path("agent_perimeter/census").rglob("*.py"):
        for name in _imports(path):
            if name.startswith(FORBIDDEN_PREFIXES):
                offences.append(f"{path}: {name}")
    assert offences == [], f"census reached a live-traffic module: {offences}"


TIER3 = Path("agent_perimeter/census/tier3.py")
_METHOD_RE = re.compile(r"^[a-z]+/[a-zA-Z]+$")


def test_every_module_but_tier3_talks_only_to_the_allowed_hosts() -> None:
    """Tiers 1-2 are artifact-only: the host list is closed and literal."""
    allowed = {
        "registry.modelcontextprotocol.io",
        "pypi.org",
        "registry.npmjs.org",
        "pypistats.org",
        "api.npmjs.org",
    }
    src = "\n".join(
        p.read_text(encoding="utf-8")
        for p in Path("agent_perimeter/census").rglob("*.py")
        if p != TIER3
    )
    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts <= allowed, f"unexpected host in census: {hosts - allowed}"


def test_tier3_sends_exactly_one_method_and_owns_no_host() -> None:
    """Tier 3's targets come from the frame, so it is constrained by shape, not by host.

    This is the guarantee that makes a live `server/discover` passive discovery
    rather than an active probe. It must be impossible to widen by accident.
    """
    src = TIER3.read_text(encoding="utf-8")

    methods = {
        node.value
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _METHOD_RE.fullmatch(node.value)
    }
    assert methods == {"server/discover"}, f"tier3 may send only server/discover, found {methods}"

    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts == set(), f"tier3 must take every target from the frame, found {hosts}"
```

The second test is why Tier 3 is confined to one module. `methods == {"server/discover"}`
is an **equality, not a subset**: adding `initialize` or `tools/list` fails it, and so does
deleting the constant the request is built from — a guard that silently passes once the
thing it guards is removed is worse than no guard. Step 3 breaks both directions.

It walks the **AST**, not the raw source, so a docstring explaining which methods Tier 3
deliberately does *not* send cannot false-fire it; a substring regex over the source does.
Both directions were exercised against synthetic modules before this plan shipped.

The strictness is deliberate and worth stating, because a future contributor will hit it:
*any* `word/word` string constant in `tier3.py` fails this test, not just a JSON-RPC method.
The module is thirty lines whose entire job is one request. There is no legitimate second
path-shaped constant, and permitting one is how the boundary erodes.

Run: `uv run pytest tests/census/test_passive_only.py`
Expected: passes trivially now (no `run.py` yet) — **which is why Step 3 deliberately tries to break it.**

- [ ] **Step 2: GREEN — the pipeline**

Create `agent_perimeter/census/run.py`:

```python
"""Census orchestration. Registry, then artifacts. No live server, ever."""

from __future__ import annotations

import hashlib
import inspect
from datetime import UTC, datetime

from agent_perimeter.census import artifacts, detect, fetch, sample


def method_hash() -> str:
    """Hash of the collection code itself, so a published number names its method.

    B9 requires versioned results. Hashing the four modules that decide what gets
    collected means a changed method cannot silently reuse an old report's label.
    """
    h = hashlib.sha256()
    for module in (fetch, artifacts, detect, sample):
        h.update(inspect.getsource(module).encode())
    return h.hexdigest()[:16]


def run_census(session, client, *, endpoint: str, tier2_n: int) -> CensusRun:
    started = datetime.now(UTC)
    log = fetch.FetchLog()
    run = CensusRun(
        started_at=started,
        population_size=0,
        tool_version=__version__,
        method_hash=method_hash(),
        tier2_n=tier2_n,
        registry_endpoint=endpoint,
    )
    session.add(run)
    session.flush()

    entries = list(fetch.paginate(client, endpoint, log))
    run.population_size = len(entries)

    ranked = sample.rank(client, entries)
    tier2 = {r.entry.registry_id for r in sample.top_n(ranked, tier2_n)}

    for entry in entries:
        record = _record_for(run, entry, ranked)
        if entry.registry_id in tier2 and entry.coords is not None:
            result = artifacts.fetch_artifact(client, entry.coords)
            record.fetch_status = result.status.value
            record.fetch_detail = result.detail
            if result.root is not None:
                fp = detect.detect_features(result.root)
                record.sdk_version = fp.sdk_version
                record.feature_set_json = {
                    "features": sorted(f.value for f in fp.features),
                    "derivation": fp.claim.derivation.value,
                    "confidence": fp.claim.confidence,
                    "caveat": fp.claim.caveat,
                    "is_unknown": fp.is_unknown,
                }
        session.add(record)

    run.fetch_failures = log.failures + _record_failures(session, run)
    run.finished_at = datetime.now(UTC)
    session.commit()
    return run
```

- [ ] **Step 3: Prove the guard bites**

Temporarily add `from agent_perimeter.transport import streamable_http` to `run.py`, then:

Run: `uv run pytest tests/census/test_passive_only.py`
Expected: **fails** with `census reached a live-traffic module: agent_perimeter/census/run.py: agent_perimeter.transport.streamable_http`.

Remove the import. Re-run: passes. A guard that has never been seen to fail is not known to work.

- [ ] **Step 4: The CLI command**

Add to `agent_perimeter/cli.py`:

```python
@app.command()
def census(
    endpoint: Annotated[str, typer.Option(help="Registry API base URL.")] = DEFAULT_REGISTRY,
    tier2_n: Annotated[int, typer.Option(help="Tier-2 packages per ecosystem.")] = 200,
    out: Annotated[Path, typer.Option(help="Directory for the report and raw data.")] = Path(
        "docs/census"
    ),
) -> None:
    """Collect a passive census of the public MCP registry.

    Reads the registry API and published package artifacts. Never connects to a
    third-party MCP server.
    """
```

- [ ] **Step 5: Run it small, end to end**

```bash
uv run agent-perimeter census --tier2-n 5 --out /tmp/census-smoke
```

Expected: completes; prints population size, tier-2 `n`, fetch failures, and the method hash. Confirm `fetch_failures` is printed even when zero — a number that only appears when it is bad is a number nobody trusts.

- [ ] **Step 6: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/run.py agent_perimeter/cli.py tests/census/
git commit -m "feat: census pipeline with a structural passive-only guarantee"
```

---

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

### Task 8: Coordinated disclosure policy

**Files:**
- Create: `docs/security.md`
- Create: `SECURITY.md`
- Test: `tests/docs/test_security_policy.py`

**Interfaces:** none in code. The test is a docs lint, and it exists because a policy that drifts from what the tool actually does is worse than no policy.

DoD 8 names `docs/security.md`; GitHub looks for `SECURITY.md` at the root. `docs/security.md` is canonical and `SECURITY.md` is a short pointer carrying the contact address, so the two can never disagree on the one field that matters.

- [ ] **Step 1: RED — the policy must contain what the brief requires**

Create `tests/docs/test_security_policy.py`:

```python
import re
from pathlib import Path

POLICY = Path("docs/security.md")
REQUIRED_SECTIONS = [
    "## Reporting a vulnerability in Agent Perimeter",
    "## What we do when we find something in your server",
    "## Embargo",
    "## Right of reply",
    "## Secrets",
    "## What we publish",
    "## Digest salt release",
]


def test_every_required_section_is_present() -> None:
    body = POLICY.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in body, f"missing: {section}"


def test_the_embargo_length_matches_the_decision() -> None:
    assert "90 days" in POLICY.read_text(encoding="utf-8")


def test_secrets_bypass_the_embargo_clock() -> None:
    body = POLICY.read_text(encoding="utf-8").lower()
    assert "never publish" in body and "never validate" in body


def test_root_pointer_carries_the_same_contact() -> None:
    contact = re.search(r"<([^>]+@[^>]+)>", POLICY.read_text(encoding="utf-8"))
    assert contact is not None
    assert contact.group(1) in Path("SECURITY.md").read_text(encoding="utf-8")
```

Run: `uv run pytest tests/docs/`
Expected: `FileNotFoundError: docs/security.md`

- [ ] **Step 2: GREEN — write the policy**

Create `docs/security.md` covering, under the exact headings above:

- **Reporting a vulnerability in Agent Perimeter** — contact address, PGP key or GitHub private advisory, expected acknowledgement time.
- **What we do when we find something in your server** — we contact the maintainer at the address published in the registry entry or repository, with the finding, the reproduction, and the date we intend to publish aggregate statistics.
- **Embargo — 90 days** from first contact. Aggregate statistics may publish before the clock expires because they name nobody; nothing that identifies a server publishes at any point, before or after.
- **Right of reply** — a maintainer may dispute a finding, supply context, or request that the check be re-run against a corrected release. Disputed findings are re-run, and the outcome is recorded in the changelog whichever way it goes.
- **Secrets** — a credential discovered in a public artifact is reported to the owner and the hosting platform immediately. **It bypasses the embargo clock entirely. It is never published, never included in raw data, and never validated against a live service.**
- **What we publish** — aggregate statistics only. No named third-party server, reply or no reply. Raw data keyed by digest.
- **Digest salt release** — the per-run salt is published when the embargo expires; until then, digests are stable pseudonyms so anyone can verify the arithmetic without being handed a target list.

Create `SECURITY.md` at the root: three sentences plus the contact address plus a link to `docs/security.md`.

- [ ] **Step 3: Wire into CI**

Add `uv run pytest tests/docs/` to the CI test job so the policy cannot silently drift from the embargo decision.

- [ ] **Step 4: Commit**

```bash
uv run pytest tests/docs/
git add docs/security.md SECURITY.md tests/docs/ .github/workflows/ci.yml
git commit -m "docs: coordinated disclosure policy with an enforced structure (DoD 8)"
```

---

### Task 9: The API

**Files:**
- Create: `agent_perimeter/api/__init__.py`
- Create: `agent_perimeter/api/app.py`
- Create: `agent_perimeter/api/schemas.py`
- Create: `agent_perimeter/api/events.py`
- Modify: `agent_perimeter/model/scope.py` (structured `missing_field` on the exception)
- Test: `tests/api/test_scans.py`
- Test: `tests/api/test_refusal.py`

**Interfaces:**
- Produces: `create_app() -> FastAPI`; routes `POST /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/events` (SSE), `GET /api/scans/{id}/findings`, `GET /api/scans/{id}/graph`, `GET /api/scans/{id}/report.sarif`, `GET /api/census/runs/{id}`.
- Consumes: the Week 1–3 scan pipeline, `ScopeFile`, `AuthorizationRequired`, `require_scope`, `to_sarif`, `build_graph`.

The API's job is to expose what already works, not to reimplement it. One rule matters: **the refusal path must be identical to the CLI's.** If the UI can start an active scan that the CLI would refuse, the scope-file constraint has a hole in it, and the hole is in the surface a buyer actually clicks.

**One additive change to Week 1 Task 3 is needed first.** `AuthorizationRequired` currently carries the failing field name only inside its message string. The API has to put that field in a JSON body and the UI has to point at the right input, and neither should be regexing an English sentence. Add the attribute without touching the messages, so Week 1's tests keep passing unchanged:

```python
class AuthorizationRequired(Exception):
    """Raised when an active check is attempted without valid authorisation."""

    def __init__(self, message: str, *, missing_field: str) -> None:
        super().__init__(message)
        self.missing_field = missing_field
```

Then pass `missing_field="scope_file"`, `"target"`, `"expires_on"` or `"attestation"` at each of `require_scope`'s existing raise sites. Add one test to `tests/model/test_scope.py` asserting the attribute is set on every raise path — an unstructured error is the kind of thing that quietly becomes structured-ish later.

- [ ] **Step 1: RED — the refusal, first**

Create `tests/api/test_refusal.py`:

```python
from fastapi.testclient import TestClient

from agent_perimeter.api.app import create_app

client = TestClient(create_app())


def test_active_mode_without_a_scope_file_is_refused() -> None:
    r = client.post("/api/scans", json={"target": "https://example.invalid/mcp", "mode": "active"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "authorization_required"
    assert body["missing_field"]
    assert "scope file" in body["message"].lower()


def test_the_refusal_names_the_specific_missing_attestation_field() -> None:
    scope = {"target": "https://example.invalid/mcp", "authorising_party": "Acme Ltd"}
    r = client.post(
        "/api/scans",
        json={"target": "https://example.invalid/mcp", "mode": "active", "scope_file": scope},
    )
    assert r.status_code == 422
    assert r.json()["missing_field"] == "attestation"


def test_passive_mode_needs_no_scope_file() -> None:
    r = client.post("/api/scans", json={"target": "https://example.invalid/mcp", "mode": "passive"})
    assert r.status_code == 202


def test_the_api_and_the_cli_refuse_on_the_same_condition() -> None:
    """One authorisation rule, one implementation. Two would eventually disagree."""
    import inspect

    from agent_perimeter.api import app as api_app
    from agent_perimeter.model.scope import require_scope

    assert "require_scope" in inspect.getsource(api_app)
```

Run: `uv run pytest tests/api/`
Expected: `ModuleNotFoundError: agent_perimeter.api.app`

- [ ] **Step 2: GREEN — the app**

Create `agent_perimeter/api/app.py`:

```python
"""HTTP surface over the existing scan pipeline. It adds no security decisions."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_perimeter.model.scope import AuthorizationRequired, require_scope


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Perimeter", docs_url="/api/docs")

    @app.exception_handler(AuthorizationRequired)
    async def _refusal(request: Request, exc: AuthorizationRequired) -> JSONResponse:
        # Copy rule: what happened, what to do, no apology.
        return JSONResponse(
            status_code=422,
            content={
                "error": "authorization_required",
                "missing_field": exc.missing_field,
                "message": (
                    f"Active checks need a scope file with {exc.missing_field}. "
                    "Attach one and re-run."
                ),
            },
        )

    app.include_router(scans.router, prefix="/api")
    app.include_router(census.router, prefix="/api")
    return app
```

`POST /api/scans` calls `require_scope(...)` for active mode before enqueuing anything — the same function the CLI and every active check call. No second implementation exists.

- [ ] **Step 3: The event stream**

`GET /api/scans/{id}/events` emits SSE frames, one per check completion:

```json
{"check_id": "revision.cache_scope", "status": "passed", "elapsed_ms": 41,
 "phase": "revision", "completed": 12, "total": 29}
```

and a terminal frame carrying `skipped` with per-check reasons. **Skipped checks are in the stream, not omitted** — spec §7.3: a skipped check is never silently absent from the count, and the live screen is where that rule is most tempting to break.

- [ ] **Step 4: Verify against a fixture**

```bash
uv run uvicorn agent_perimeter.api.app:create_app --factory --port 8000 &
curl -sS -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"python /server.py","mode":"active"}' | jq
```

Expected: `422` with `missing_field` naming the first absent attestation field. **Screenshot this** — brief §7 calls the refusal a selling point, and it belongs in the deck.

- [ ] **Step 5: Commit**

```bash
uv run pytest tests/api/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/api/ agent_perimeter/model/scope.py tests/api/ tests/model/test_scope.py
git commit -m "feat: API over the scan pipeline, refusing on the same rule as the CLI"
```

---

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

### Task 12: Screen 2 — live scan

**Files:**
- Create: `web/app/scans/[id]/page.tsx`
- Create: `web/app/components/PhaseGroup.tsx`
- Test: `web/tests/live-scan.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/events` (SSE), `Skeleton`, `RunTimeline`, `QuotaStrip`.

Brief §7 screen 2. **Skeletons, never spinners** (`00` §5.5). `QuotaStrip` appears only if a model lane engages — which, given the determinism budget, is the exception rather than the rule, and the screen should make that visible rather than hide it.

- [ ] **Step 1: RED**

```ts
test("checks stream in grouped by phase", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.getByRole("group", { name: /revision/i })).toBeVisible();
  await expect(page.getByTestId("check-row")).toHaveCount(29, { timeout: 10_000 });
});

test("no spinner is ever rendered", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.locator("[data-loading='spinner']")).toHaveCount(0);
  await expect(page.getByTestId("skeleton").first()).toBeVisible();
});

test("skipped checks are shown with a reason, not omitted", async ({ page }) => {
  await page.goto("/scans/1?fixture=degraded");
  const skipped = page.getByTestId("check-row").filter({ hasText: /skipped/i });
  await expect(skipped).toHaveCount(1);
  await expect(skipped).toContainText(/no model provider/i);
});

test("the quota strip is absent when no model lane engages", async ({ page }) => {
  await page.goto("/scans/1?fixture=deterministic");
  await expect(page.getByTestId("quota-strip")).toHaveCount(0);
});

test("progress is announced to assistive technology", async ({ page }) => {
  await page.goto("/scans/1?fixture=streaming");
  await expect(page.getByRole("status")).toContainText(/\d+ of 29/);
});
```

- [ ] **Step 2: GREEN**

`EventSource` against the SSE endpoint, checks grouped by phase, skeleton rows for pending checks, an `aria-live="polite"` status region reporting `n of 29`, and a terminal summary reading *"No findings for the checks that ran"* plus the skipped count when the run is clean — never *"You're secure!"*.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/live-scan.spec.ts
git add web/app/scans web/tests/live-scan.spec.ts
git commit -m "feat: live scan screen with skeletons and visible skipped checks"
```

---

### Task 13: Screen 3 — findings, with the revision conformance strip

**Files:**
- Create: `web/app/scans/[id]/findings/page.tsx`
- Create: `web/app/components/ConformanceStrip.tsx`
- Create: `web/app/components/FindingRow.tsx`
- Test: `web/tests/findings.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/findings`, `FindingsTable`, `EvidencePane`, `SeverityBadge`, `Claim`, `ProvenanceRail`.

Brief §7 screen 3 plus the two deltas from spec §10: a **derivation / feature column** showing which observed features made each check applicable, and the **revision conformance strip** heading the screen — *"claims 2026-07-28 · observes 7 of 10 features · 3 conformance gaps"*. The strip is the differentiator rendered in about four seconds, and it is a header element rather than a new screen.

- [ ] **Step 1: RED**

```ts
test("the conformance strip states claim, observation and gaps", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mismatch");
  const strip = page.getByTestId("conformance-strip");
  await expect(strip).toContainText("claims 2026-07-28");
  await expect(strip).toContainText(/observes \d+ of \d+ features/);
  await expect(strip).toContainText(/\d+ conformance gaps?/);
});

test("a server claiming nothing reads as unknown, not as non-compliant", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=unknown-revision");
  await expect(page.getByTestId("conformance-strip")).toContainText(/revision unknown/i);
});

test("every finding row shows its CWE and a taxonomy reference", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  for (const row of await page.getByTestId("finding-row").all()) {
    await expect(row.getByTestId("cwe")).toHaveText(/CWE-\d+/);
    await expect(row.getByTestId("taxonomy")).not.toHaveText("");
  }
});

test("expanding a row reveals the reproduction command with a copy button", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("finding-row").first().click();
  await expect(page.getByTestId("reproduction")).toBeVisible();
  await expect(page.getByRole("button", { name: /copy/i })).toBeEnabled();
});

test("clicking a claim opens the provenance rail", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().click();
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("the rail also opens from the keyboard", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  await page.getByTestId("claim").first().focus();
  await page.keyboard.press("Meta+Period");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("csv export carries the provenance column", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=mixed");
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: /export csv/i }).click(),
  ]);
  const body = await (await download.createReadStream())!.toArray();
  expect(body.join("")).toContain("provenance");
});

test("empty findings never claim the target is secure", async ({ page }) => {
  await page.goto("/scans/1/findings?fixture=clean");
  const empty = page.getByTestId("empty-state");
  await expect(empty).toContainText("No findings for the checks that ran");
  await expect(empty).toContainText(/\d+ skipped/);
  await expect(empty).not.toContainText(/secure/i);
});
```

- [ ] **Step 2: GREEN**

Virtualised `FindingsTable`, severity glyph plus label, filters on severity / check / taxonomy, row expansion into `EvidencePane` with highlight ranges, SARIF / JSON / CSV export, and `ConformanceStrip` reading its three numbers from the scan's `revision_claimed`, observed `FeatureSet` and the `conformance_mismatch` findings.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/findings.spec.ts
git add web/app web/tests/findings.spec.ts
git commit -m "feat: findings screen with the revision conformance strip"
```

---

### Task 14: Screen 4 — the capability graph

**Files:**
- Create: `web/app/scans/[id]/graph/page.tsx`
- Create: `web/app/components/CapabilityGraph.tsx`
- Create: `web/app/components/EdgeTooltip.tsx`
- Test: `web/tests/graph.spec.ts`

**Interfaces:**
- Consumes: `GET /api/scans/{id}/graph`, `Claim`, `ProvenanceRail`.

Brief §7 screen 4, the signature moment, and the screen the deck leads with. Three requirements are load-bearing:

- Any node satisfying a policy predicate **pulses once, amber, on first render**, then holds a static ring. One orchestrated moment — not scattered effects, and not a loop.
- Hovering or focusing an edge shows **why** the capability was inferred: schema, description, or probe. B9 again — an edge inferred from prose and an edge confirmed by a probe are not the same claim and must not look the same.
- Under `prefers-reduced-motion` the pulse does not run and the ring is present from the first frame. The information must not live in the animation.

A force-directed graph is also the easiest screen in the product to make unusable with a keyboard, so the accessible path is built first and the canvas second.

- [ ] **Step 1: RED**

```ts
test("a policy-flagged node pulses once and then holds a ring", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "playing");
  await expect(node).toHaveAttribute("data-pulse", "done", { timeout: 3_000 });
  await expect(node).toHaveAttribute("data-ring", "true");
});

test("reduced motion skips the pulse and keeps the ring", async ({ browser }) => {
  const page = await (await browser.newContext({ reducedMotion: "reduce" })).newPage();
  await page.goto("/scans/1/graph?fixture=deputy");
  const node = page.getByTestId("node-flagged").first();
  await expect(node).toHaveAttribute("data-pulse", "skipped");
  await expect(node).toHaveAttribute("data-ring", "true");
});

test("every edge exposes its derivation", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  for (const edge of await page.getByTestId("edge").all()) {
    await expect(edge).toHaveAttribute("data-derivation", /schema|description|probe|artifact/);
  }
});

test("a probe-derived edge is visually distinct from a description-derived one", async ({
  page,
}) => {
  await page.goto("/scans/1/graph?fixture=mixed-derivation");
  const probe = page.locator("[data-derivation='probe']").first();
  const desc = page.locator("[data-derivation='description']").first();
  expect(await probe.getAttribute("stroke-dasharray")).not.toBe(
    await desc.getAttribute("stroke-dasharray"),
  );
});

test("the graph is fully navigable from the keyboard", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  await page.keyboard.press("Tab");
  await expect(page.getByTestId("node").first()).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("complementary", { name: /provenance/i })).toBeVisible();
});

test("a text alternative lists every node and edge", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=deputy");
  const table = page.getByRole("table", { name: /capability edges/i });
  await expect(table).toBeVisible();
  await expect(table.getByRole("row")).toHaveCount(await page.getByTestId("edge").count() + 1);
});

test("an empty graph explains itself", async ({ page }) => {
  await page.goto("/scans/1/graph?fixture=no-tools");
  await expect(page.getByTestId("empty-state")).toContainText(/no tools were enumerated/i);
});
```

- [ ] **Step 2: GREEN — accessible table first, canvas second**

Render the edge table (always in the DOM, visually secondary), then the force-directed graph over the same data. Focus moves through nodes in the table's order, so keyboard and visual navigation cannot diverge. Derivation maps to stroke pattern **and** a legend entry — never colour alone.

- [ ] **Step 3: REFACTOR — the pulse belongs to render, not to a timer**

```ts
// ponytail: pulse is a one-shot CSS animation keyed on first paint, not a JS timer.
// A timer would re-fire on re-render and turn the one orchestrated moment into a
// nervous tic, which is the exact failure 00 §5.3 warns about.
```

- [ ] **Step 4: Commit**

```bash
npx playwright test tests/graph.spec.ts
git add web/app web/tests/graph.spec.ts
git commit -m "feat: capability graph with per-edge derivation and a single pulse"
```

---

### Task 15: Screen 5 — drift stub

**Files:**
- Create: `web/app/scans/[id]/drift/page.tsx`
- Test: `web/tests/drift.spec.ts`

**Interfaces:**
- Consumes: `description_hash` and `drift_event` (already in the v1 schema per the brief), `DiffView`, `EmptyState`.

Brief §7 screen 5 is a v2 surface stubbed in v1. Stubbed means **honest about being a stub** — it renders real data when two scans of the same target exist, and an empty state naming what it needs when they do not. It does not render fake data, and it does not promise a subscription that has not been built.

A silently-changed tool description rendered as a word-level red-lined diff is the most visceral artifact in the product, so the diff itself is real even though the monitoring around it is not.

- [ ] **Step 1: RED**

```ts
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
  await expect(diff.getByTestId("removed")).toContainText("read the config file");
  await expect(diff.getByTestId("added")).toContainText("read any file");
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
```

- [ ] **Step 2: GREEN**

`RunTimeline` of scans for the target, `DiffView` on `description_hash` mismatches, absolute ISO dates (never "3 days ago" — this is an audit artifact), and an empty state that states the precondition.

- [ ] **Step 3: Commit**

```bash
npx playwright test tests/drift.spec.ts
git add web/app web/tests/drift.spec.ts
git commit -m "feat: drift screen rendering real diffs, honest about being a v1 stub"
```

---

### Task 16: Accessibility, keyboard and print verification

**Files:**
- Create: `web/tests/a11y.spec.ts`
- Create: `web/tests/print.spec.ts`
- Create: `web/app/print.css`
- Modify: `.github/workflows/ci.yml`
- Create: `docs/evidence/print-report.png`, `docs/evidence/print-census.png`

**Interfaces:** none. This task closes DoD 9, and it is a verification task, not a feature task.

`00` §5.5 is not negotiable and two of the four target markets are literally regulated for accessibility. The gate is **zero serious and zero critical axe violations on all six screens**, full keyboard operation, and correct printing.

**Screen 6 is not a Next.js route.** Week 3 built it as static HTML from `report/html.py`, deliberately, so publication does not depend on the application. It is therefore verified as a file, not as a route: a pretest step renders one into `web/tests/fixtures/report.html` and Playwright's `webServer` config serves that directory at `/static/`. Testing the real artifact rather than a route that resembles it is the whole reason the decoupling was worth making.

```ts
// web/playwright.config.ts — serve the static artifacts alongside the app
webServer: [
  { command: "npm run dev", url: "http://localhost:3000", reuseExistingServer: true },
  { command: "npx serve -p 4173 tests/fixtures", url: "http://localhost:4173" },
],
```

- [ ] **Step 1: RED — axe across every screen**

Create `web/tests/a11y.spec.ts`:

```ts
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const SCREENS = [
  ["scan setup", "/"],
  ["live scan", "/scans/1?fixture=streaming"],
  ["findings", "/scans/1/findings?fixture=mixed"],
  ["capability graph", "/scans/1/graph?fixture=deputy"],
  ["drift", "/scans/2/drift?fixture=changed-description"],
  // Screen 6 is the static artifact from report/html.py, served on 4173, not a route.
  ["report", "http://localhost:4173/report.html"],
] as const;

for (const [name, path] of SCREENS) {
  test(`${name} has no serious or critical axe violations`, async ({ page }) => {
    await page.goto(path);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    const blocking = results.violations.filter((v) =>
      ["serious", "critical"].includes(v.impact ?? ""),
    );
    expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
  });

  test(`${name} is fully operable from the keyboard`, async ({ page }) => {
    await page.goto(path);
    const reachable = new Set<string>();
    for (let i = 0; i < 60; i++) {
      await page.keyboard.press("Tab");
      const id = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));
      if (id) reachable.add(id);
    }
    const interactive = await page.getByRole("button").count();
    expect(reachable.size).toBeGreaterThanOrEqual(Math.min(interactive, 1));
  });

  test(`${name} has a visible focus ring`, async ({ page }) => {
    await page.goto(path);
    await page.keyboard.press("Tab");
    const outline = await page.evaluate(
      () => getComputedStyle(document.activeElement!).outlineStyle,
    );
    expect(outline).not.toBe("none");
  });

  test(`${name} is usable at 375px`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(path);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    );
    expect(overflow).toBe(false);
  });
}
```

- [ ] **Step 2: RED — print**

Create `web/tests/print.spec.ts`:

```ts
test("the report prints without interactive chrome", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  await expect(page.getByTestId("nav")).toBeHidden();
  await expect(page.getByRole("button", { name: /export/i })).toBeHidden();
  await expect(page.getByTestId("methodology-footer")).toBeVisible();
  await page.screenshot({ path: "../docs/evidence/print-report.png", fullPage: true });
});

test("severity survives greyscale", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  for (const badge of await page.getByTestId("severity-badge").all()) {
    await expect(badge).toHaveAttribute("data-glyph", /.+/);
  }
});

test("no finding row is split across a page break", async ({ page }) => {
  await page.goto("http://localhost:4173/report.html");
  await page.emulateMedia({ media: "print" });
  const broken = await page.evaluate(() =>
    [...document.querySelectorAll("[data-testid='finding-row']")].filter(
      (el) => getComputedStyle(el).breakInside !== "avoid",
    ).length,
  );
  expect(broken).toBe(0);
});
```

- [ ] **Step 3: GREEN — render the static fixture, then fix whatever the tests find**

The report fixture is generated, not committed, so it can never drift from the emitter:

```json
"scripts": { "pretest": "cd .. && uv run agent-perimeter scan --target fixture://mixed --html web/tests/fixtures/report.html" }
```

Run both suites and fix. Do not weaken an assertion to make it pass; the assertion is the deliverable.

- [ ] **Step 4: Wire into CI**

Add to `.github/workflows/ci.yml`:

```yaml
  web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22", cache: npm, cache-dependency-path: web/package-lock.json }
      - run: npm ci
        working-directory: web
      - run: npx playwright install --with-deps chromium
        working-directory: web
      - run: npx tsc --noEmit && npm run lint
        working-directory: web
      - run: npx playwright test
        working-directory: web
      - uses: actions/upload-artifact@v4
        if: failure()
        with: { name: playwright-report, path: web/playwright-report/ }
```

- [ ] **Step 5: Print the census report too**

The census report is a second static artifact and needs the same treatment. Extend the `pretest` script to render it into `web/tests/fixtures/census.html`, then add to `print.spec.ts`:

```ts
test("the census report prints with its methodology intact", async ({ page }) => {
  await page.goto("http://localhost:4173/census.html");
  await page.emulateMedia({ media: "print" });
  for (const id of ["population-size", "tier2-n", "unknown-count", "fetch-failures"]) {
    await expect(page.getByTestId(id)).toBeVisible();
  }
  await expect(page.getByTestId("term-definitions")).toBeVisible();
  await page.screenshot({ path: "../docs/evidence/print-census.png", fullPage: true });
});
```

**This is the artifact that gets emailed to a journalist.** If it prints badly, or if the methodology drops off the printed page while the headline percentage survives, the work is not done — that failure mode is precisely the one this project exists to argue against.

- [ ] **Step 6: Commit**

```bash
git add web/tests web/app/print.css .github/workflows/ci.yml docs/evidence/
git commit -m "test: axe, keyboard, responsive and print verification across six screens (DoD 9)"
```

---

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
