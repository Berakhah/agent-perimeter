"""Tier-2 selection is a seeded uniform random sample per ecosystem: no network,
reproducible from the seed, and never weighted by popularity."""

from collections import Counter
from pathlib import Path

from agent_perimeter.census import sample
from agent_perimeter.model.census import Ecosystem
from tests.census.factories import entries


def test_same_seed_and_population_gives_the_same_selection() -> None:
    population = entries(npm=30, pypi=20, remote_only=10)
    a = sample.select(population, n=5, seed=42)
    b = sample.select(list(reversed(population)), n=5, seed=42)
    assert [e.registry_id for e in a] == [e.registry_id for e in b]


def test_different_seeds_give_different_selections() -> None:
    population = entries(npm=200)
    assert {e.registry_id for e in sample.select(population, n=20, seed=1)} != {
        e.registry_id for e in sample.select(population, n=20, seed=2)
    }


def test_n_is_per_ecosystem_and_capped_by_the_pool() -> None:
    population = entries(npm=30, pypi=3)
    chosen = sample.select(population, n=5, seed=7)
    by_eco = Counter(e.coords.ecosystem for e in chosen if e.coords is not None)
    assert by_eco == {Ecosystem.NPM: 5, Ecosystem.PYPI: 3}


def test_entries_without_coords_are_never_selected() -> None:
    population = entries(npm=2, remote_only=10)
    assert all(e.coords is not None for e in sample.select(population, n=50, seed=0))


def test_sample_module_makes_no_network_calls() -> None:
    src = Path("agent_perimeter/census/sample.py").read_text(encoding="utf-8")
    assert "httpx" not in src and "https://" not in src


def test_selection_source_is_a_stable_label() -> None:
    assert sample.SELECTION_SOURCE == "seeded_random"
