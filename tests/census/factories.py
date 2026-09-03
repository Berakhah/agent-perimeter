"""Test factory for RankedEntry populations used by tier-2 sampling tests."""

from __future__ import annotations

from collections.abc import Sequence

from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.census.sample import RankedEntry, RankSource
from agent_perimeter.model.census import Ecosystem, PackageCoords

_SOURCE_BY_ECOSYSTEM = {
    Ecosystem.PYPI: RankSource.PYPI_RECENT_DOWNLOADS,
    Ecosystem.NPM: RankSource.NPM_LAST_MONTH_DOWNLOADS,
}


def ranked(
    specs: Sequence[tuple[str, int | None] | tuple[str, int | None, str]],
) -> list[RankedEntry]:
    """Build a RankedEntry population from (name, downloads[, ecosystem]) tuples.

    `ecosystem` defaults to "pypi" when omitted - most `top_n` tests only care
    about ranking within a single ecosystem and would otherwise have to spell
    it out on every row.
    """
    out: list[RankedEntry] = []
    for spec in specs:
        match spec:
            case (name, downloads, eco_str):
                pass
            case (name, downloads):
                eco_str = "pypi"
        eco = Ecosystem(eco_str)
        entry = RegistryEntry(
            registry_id=name,
            name=name,
            coords=PackageCoords(ecosystem=eco, name=name),
            repository_url=None,
        )
        source = RankSource.UNAVAILABLE if downloads is None else _SOURCE_BY_ECOSYSTEM[eco]
        out.append(RankedEntry(entry=entry, downloads=downloads, rank_source=source))
    return out
