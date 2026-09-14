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
    """Up to n entries per ecosystem, drawn uniformly at random with `seed`.

    The pool is sorted by registry_id before the draw so the result depends
    only on the population and the seed, never on the order the registry
    happened to page entries out in.
    """
    rng = random.Random(seed)  # noqa: S311 -- reproducibility requires a seedable PRNG, not `secrets`
    out: list[RegistryEntry] = []
    for eco in Ecosystem:
        pool = sorted(
            (e for e in entries if e.coords is not None and e.coords.ecosystem is eco),
            key=lambda e: e.registry_id,
        )
        out.extend(rng.sample(pool, min(n, len(pool))))
    return out
