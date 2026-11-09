"""The labelled corpus behind the published precision and recall.

Clean controls are half the corpus by design. A detector that fires on
everything has perfect recall and is worthless, so every positive case is
paired with a near-miss negative differing in exactly the detail that should
decide the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

CORPUS_YAML = Path(__file__).parents[2] / "tests" / "fixtures" / "corpus.yaml"


@dataclass(frozen=True)
class CorpusCase:
    id: str
    revision: str
    flaw: str
    baseline_flaw: str | None = None
    expect_findings: tuple[str, ...] = ()
    expect_clean: tuple[str, ...] = ()
    note: str = ""
    transcript: str | None = None


def _load(path: Path) -> tuple[str, list[CorpusCase]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = [
        CorpusCase(
            id=row["id"],
            revision=str(row["revision"]),
            flaw=row["flaw"],
            baseline_flaw=row.get("baseline_flaw"),
            expect_findings=tuple(row.get("expect_findings", ())),
            expect_clean=tuple(row.get("expect_clean", ())),
            note=row.get("note", ""),
            transcript=row.get("transcript"),
        )
        for row in payload["cases"]
    ]
    return str(payload["version"]), cases


@cache
def _default() -> tuple[str, list[CorpusCase]]:
    # Read on first use, never at import: the corpus lives in the git checkout's tests/, which
    # an installed wheel doesn't have, and the HTML report imports this module's types.
    return _load(CORPUS_YAML)


def corpus_version() -> str:
    return _default()[0]


def load_corpus(path: Path | None = None) -> list[CorpusCase]:
    if path is None:
        return list(_default()[1])
    return _load(path)[1]
