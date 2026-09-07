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

