"""Registry pagination. Read-only, rate-limited, and it identifies itself.

Field names and envelope shape are confirmed against the live registry API -
see docs/methodology.md ## Census collection for the observed response and the
date it was captured. Do not "fix" the field names below to match an older
draft of this module without re-confirming against a live response first.
"""

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
    # Same placeholder repo path as agent_perimeter.cli.DEFAULT_CONTACT_URL - not
    # imported from there to avoid pulling the CLI's typer/transport dependency
    # graph into a read-only fetch module for one string.
    "(+https://github.com/Berakhah/agent-perimeter/blob/main/docs/security.md)"
)

# A page holds at most this many entries; also the signal the loud guard below
# uses to tell "the population truly ended" from "we stopped reading a cursor
# that was there".
PAGE_LIMIT = 100

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
    remotes: tuple[str, ...] = ()
    # True when `packages` contains an entry whose registryType is a *known*
    # ecosystem this module does not model (oci/nuget/mcpb) - distinct from
    # coords is None because there was no package at all. A later task deriving
    # census_record.distribution needs this to tell package_other from none
    # without re-parsing the raw registry response.
    has_unmodeled_package: bool = False


# Ecosystem (model/census.py, Task 1's file) only models pypi/npm. These are
# registryType values the registry actually uses that have no Ecosystem member
# yet - known, just unsupported, not the same fact as an unrecognised value.
_UNMODELED_REGISTRY_TYPES = frozenset({"oci", "nuget", "mcpb"})


def _registry_type(package: dict[str, object]) -> str:
    return str(package.get("registryType") or package.get("registry_name") or "").lower()


def _coords(package: dict[str, object]) -> PackageCoords | None:
    name = package.get("identifier") or package.get("name")
    if not isinstance(name, str):
        return None
    match _registry_type(package):
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


def _remotes(server: dict[str, object]) -> tuple[str, ...]:
    remotes = server.get("remotes")
    if not isinstance(remotes, list):
        return ()
    return tuple(
        remote["url"]
        for remote in remotes
        if isinstance(remote, dict) and isinstance(remote.get("url"), str)
    )


def _entry(item: dict[str, object]) -> RegistryEntry | None:
    # The envelope nests the actual record under "server"; the sibling "_meta"
    # key carries registry-assigned status, not part of the server record itself.
    server = item.get("server")
    if not isinstance(server, dict):
        return None
    name = server.get("name")
    if not isinstance(name, str) or not name:
        return None
    version = server.get("version")
    registry_id = f"{name}:{version}" if isinstance(version, str) and version else name

    coords: PackageCoords | None = None
    has_unmodeled_package = False
    packages = server.get("packages")
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, dict):
                continue
            if coords is None:
                coords = _coords(package)
            if _registry_type(package) in _UNMODELED_REGISTRY_TYPES:
                has_unmodeled_package = True

    repository = server.get("repository")
    repository_url = repository.get("url") if isinstance(repository, dict) else None
    if not isinstance(repository_url, str):
        repository_url = None

    return RegistryEntry(
        registry_id=registry_id,
        name=name,
        coords=coords,
        repository_url=repository_url,
        remotes=_remotes(server),
        has_unmodeled_package=has_unmodeled_package,
    )


def _retry_after_seconds(header_value: str | None) -> float:
    if header_value is None:
        return MIN_INTERVAL_S
    try:
        return max(float(header_value), 0.0)
    except ValueError:
        return MIN_INTERVAL_S


def _get_page(
    client: httpx.Client,
    endpoint: str,
    params: dict[str, str | int],
    log: FetchLog,
    page: int,
    max_retries: int,
) -> dict[str, object] | None:
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(max_retries):
        try:
            response = client.get(endpoint, params=params, headers=headers, timeout=10.0)
        except httpx.TimeoutException:
            if attempt + 1 >= max_retries:
                log.record(
                    FetchStatus.TIMEOUT,
                    f"page {page}: timed out, gave up after {max_retries} attempts",
                )
                return None
            continue

        if response.status_code == 429:
            if attempt + 1 >= max_retries:
                log.record(
                    FetchStatus.THROTTLED,
                    f"page {page}: throttled, gave up after {max_retries} attempts",
                )
                return None
            time.sleep(_retry_after_seconds(response.headers.get("Retry-After")))
            continue

        if response.status_code != 200:
            log.record(
                FetchStatus.PARSE_ERROR, f"page {page}: unexpected status {response.status_code}"
            )
            return None

        try:
            body = response.json()
        except ValueError:
            log.record(FetchStatus.PARSE_ERROR, f"page {page}: response body was not valid JSON")
            return None
        if not isinstance(body, dict):
            log.record(FetchStatus.PARSE_ERROR, f"page {page}: response body was not a JSON object")
            return None
        return body

    log.record(FetchStatus.TIMEOUT, f"page {page}: gave up after {max_retries} attempts")
    return None


def paginate(
    client: httpx.Client,
    endpoint: str,
    log: FetchLog,
    *,
    max_retries: int = 3,
) -> Iterator[RegistryEntry]:
    seen_names: set[str] = set()
    cursor: str | None = None
    page = 0
    while True:
        page += 1
        params: dict[str, str | int] = {"limit": PAGE_LIMIT, "version": "latest"}
        if cursor:
            params["cursor"] = cursor
        body = _get_page(client, endpoint, params, log, page, max_retries)
        if body is None:
            return

        raw_servers = body.get("servers")
        items = raw_servers if isinstance(raw_servers, list) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            entry = _entry(item)
            if entry is None or entry.name in seen_names:
                continue
            seen_names.add(entry.name)
            yield entry

        metadata = body.get("metadata")
        next_cursor = metadata.get("nextCursor") if isinstance(metadata, dict) else None
        cursor = next_cursor if isinstance(next_cursor, str) else None
        if not cursor:
            if page == 1 and len(items) >= PAGE_LIMIT:
                # A full first page with no cursor is far more likely a broken
                # cursor read (metadata key renamed, envelope reshaped) than a
                # registry that happens to hold exactly PAGE_LIMIT entries. Do
                # not report this population as complete - report it as a bug.
                log.record(
                    FetchStatus.PARSE_ERROR,
                    f"page 1 returned {len(items)} entries (== limit) with no nextCursor "
                    "- treating as a suspected pagination bug, not an exhausted population",
                )
                return
            log.record(FetchStatus.OK, f"exhausted after {page} pages")
            return
        time.sleep(MIN_INTERVAL_S)
