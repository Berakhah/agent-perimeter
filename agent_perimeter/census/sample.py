"""Tier-2 selection. Deterministic, within-ecosystem, and it states its method.

The registry API itself carries no popularity signal - see fetch.py's module
docstring and docs/methodology.md ## Census collection for the confirmed
response shape: no `downloads`, `stars`, `install_count` or equivalent field
on any entry. That absence is why ranking goes out to pypistats.org and
api.npmjs.org at all, rather than reading a field the registry never had.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

import httpx

from agent_perimeter import __version__
from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.model.census import Ecosystem

PYPI_DOWNLOADS = "https://pypistats.org/api/packages/{name}/recent"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month/{name}"

USER_AGENT = (
    f"agent-perimeter/{__version__} "
    "(+https://github.com/Berakhah/agent-perimeter/blob/main/docs/security.md)"
)

_TIMEOUT_S = 10.0

# ponytail: fixed delay before the next pypistats.org call, not a token bucket.
# pypistats rate-limits aggressively: the 2026-09-14 dry run saw 429 on 3 of 6
# probes at a 0.3s interval with no retry, which ranked most PyPI entries
# UNAVAILABLE and kept them out of tier 2 for a reason that had nothing to do
# with their downloads. The interval is now 1.0s and a 429 is retried with the
# backoff below; only a 429 on the final attempt is UNAVAILABLE. A throttled
# entry still never raises out of rank(). Swap for a token bucket if a
# published Retry-After ever demands more than a fixed wait.
MIN_INTERVAL_S = 1.0  # was 0.3; pypistats.org 429'd 3 of 6 probes at 0.3s on 2026-09-14
PYPI_429_BACKOFF_S: tuple[float, ...] = (2.0, 5.0, 10.0)

SELECTION_METHOD = (
    "The registry API itself carries no popularity, download, star, or "
    "install-count field for any entry, so tier 2 ranks against pypistats.org and "
    "api.npmjs.org instead of a field the registry never had. Tier 2 is the top n "
    "packages by download count within each ecosystem, ranked separately because "
    "PyPI recent downloads and npm last-month downloads are different measurements "
    "over different windows and are not comparable. Ties break on registry id "
    "ascending. Entries with no available download metric are excluded from tier 2 "
    "and counted in the report."
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


def _pypi_downloads(client: httpx.Client, name: str) -> int | None:
    url = PYPI_DOWNLOADS.format(name=name)
    for attempt in range(len(PYPI_429_BACKOFF_S) + 1):
        try:
            response = client.get(url, headers={"User-Agent": USER_AGENT}, timeout=_TIMEOUT_S)
        except httpx.HTTPError:
            return None
        if response.status_code == 429 and attempt < len(PYPI_429_BACKOFF_S):
            time.sleep(PYPI_429_BACKOFF_S[attempt])
            continue
        break
    if response.status_code != 200:
        return None
    try:
        doc = response.json()
    except ValueError:
        return None
    data = doc.get("data") if isinstance(doc, dict) else None
    last_month = data.get("last_month") if isinstance(data, dict) else None
    return last_month if isinstance(last_month, int) else None


def _npm_downloads(client: httpx.Client, name: str) -> int | None:
    url = NPM_DOWNLOADS.format(name=name)
    try:
        response = client.get(url, headers={"User-Agent": USER_AGENT}, timeout=_TIMEOUT_S)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        doc = response.json()
    except ValueError:
        return None
    # Unknown package: {"error": "package ... not found"} - no "downloads" key
    # at all, not a missing/null value under one.
    downloads = doc.get("downloads") if isinstance(doc, dict) else None
    return downloads if isinstance(downloads, int) else None


def rank(client: httpx.Client, entries: list[RegistryEntry]) -> list[RankedEntry]:
    """Look up a within-ecosystem download count for each entry.

    Never raises into the caller - one throttled or unknown package must not
    end a ranking pass over hundreds of entries. Any failure (429, timeout,
    non-200, unparseable body, missing field) becomes RankSource.UNAVAILABLE
    for that entry alone. An entry with no coords (a remote-only server, no
    package) is never looked up at all - there is nothing to ask pypistats.org
    or npm about.
    """
    out: list[RankedEntry] = []
    for entry in entries:
        coords = entry.coords
        if coords is None:
            out.append(RankedEntry(entry=entry, downloads=None, rank_source=RankSource.UNAVAILABLE))
            continue

        # Ecosystem (model/census.py) only ever has these two members today, so
        # mypy proves this match exhaustive - a third member would be a type
        # error here, not a silent UNAVAILABLE at run time.
        match coords.ecosystem:
            case Ecosystem.PYPI:
                downloads = _pypi_downloads(client, coords.name)
                time.sleep(MIN_INTERVAL_S)
                source = RankSource.PYPI_RECENT_DOWNLOADS
            case Ecosystem.NPM:
                downloads = _npm_downloads(client, coords.name)
                source = RankSource.NPM_LAST_MONTH_DOWNLOADS

        out.append(
            RankedEntry(
                entry=entry,
                downloads=downloads,
                rank_source=source if downloads is not None else RankSource.UNAVAILABLE,
            )
        )
    return out


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
