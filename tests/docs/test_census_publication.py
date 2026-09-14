"""Every published census run under docs/census/<date>/ must be complete,
reproducible from its own CSV, name-free, and recorded in the changelog."""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

CENSUS_DIR = Path("docs/census")
CHANGELOG = CENSUS_DIR / "CHANGELOG.md"
REQUIRED_FILES = ("census.html", "records.csv", "records.summary.json")
DATED = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _published_runs() -> list[Path]:
    return sorted(p for p in CENSUS_DIR.iterdir() if p.is_dir() and DATED.match(p.name))


def _analysis_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "census_analysis", Path("analysis/census_analysis.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_published_run_carries_the_three_artifacts() -> None:
    for run in _published_runs():
        for name in REQUIRED_FILES:
            assert (run / name).is_file(), f"{run.name} is missing {name}"


def test_every_published_run_is_named_in_the_changelog() -> None:
    body = CHANGELOG.read_text(encoding="utf-8")
    for run in _published_runs():
        assert f"## {run.name}" in body, f"CHANGELOG has no entry for {run.name}"


def test_every_published_csv_reproduces_its_own_summary() -> None:
    check = _analysis_module().check
    for run in _published_runs():
        assert check(run / "records.csv", run / "records.summary.json"), (
            f"{run.name}: records.csv does not reproduce records.summary.json"
        )


def test_published_csv_carries_digests_only() -> None:
    """Hard rule 8: no package name, URL, or registry id reaches the public CSV."""
    for run in _published_runs():
        header, *rows = (run / "records.csv").read_text(encoding="utf-8").splitlines()
        assert header == (
            "coords_digest,stratum,ecosystem,sdk_version,"
            "supports_2026_07_28,fetch_status,collected_at"
        )
        for row in rows:
            digest = row.split(",", 1)[0]
            assert re.fullmatch(r"[0-9a-f]{32}", digest), f"{run.name}: non-digest key {digest!r}"
            assert "http" not in row and "/" not in row.split(",", 1)[0]


def test_unreleased_section_is_honest_when_nothing_is_published() -> None:
    body = CHANGELOG.read_text(encoding="utf-8")
    if not _published_runs():
        assert "No census has been published yet" in body
