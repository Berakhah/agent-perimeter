"""Test factory for RegistryEntry populations used by tier-2 sampling tests."""

from __future__ import annotations

from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.model.census import Ecosystem, PackageCoords


def entry(name: str, ecosystem: Ecosystem | None) -> RegistryEntry:
    """One RegistryEntry. `ecosystem=None` builds a remote-only entry with no
    package coordinates, which tier-2 selection must never pick."""
    coords = PackageCoords(ecosystem=ecosystem, name=name) if ecosystem is not None else None
    remotes = ("https://example.invalid/mcp",) if ecosystem is None else ()
    return RegistryEntry(
        registry_id=name, name=name, coords=coords, repository_url=None, remotes=remotes
    )


def entries(*, npm: int = 0, pypi: int = 0, remote_only: int = 0) -> list[RegistryEntry]:
    """A population with distinct registry_ids: `npm` npm entries, `pypi` PyPI
    entries and `remote_only` entries with no coords, in that order."""
    out: list[RegistryEntry] = []
    out.extend(entry(f"npm-{i:03d}", Ecosystem.NPM) for i in range(npm))
    out.extend(entry(f"pypi-{i:03d}", Ecosystem.PYPI) for i in range(pypi))
    out.extend(entry(f"remote-{i:03d}", None) for i in range(remote_only))
    return out
