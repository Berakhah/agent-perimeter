"""The labelled corpus behind the published precision and recall.

Clean controls are half the corpus by design. A detector that fires on
everything has perfect recall and is worthless, so every positive case is
paired with a near-miss negative differing in exactly the detail that should
decide the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

CORPUS_YAML = Path(__file__).parents[2] / "tests" / "fixtures" / "corpus.yaml"


@dataclass(frozen=True)
class CorpusCase:
    id: str
    revision: str
    flaw: str
    expect_findings: tuple[str, ...] = ()
    expect_clean: tuple[str, ...] = ()
    note: str = ""


def _load(path: Path) -> tuple[str, list[CorpusCase]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = [
        CorpusCase(
            id=row["id"],
            revision=str(row["revision"]),
            flaw=row["flaw"],
            expect_findings=tuple(row.get("expect_findings", ())),
            expect_clean=tuple(row.get("expect_clean", ())),
            note=row.get("note", ""),
        )
        for row in payload["cases"]
    ]
    return str(payload["version"]), cases


CORPUS_VERSION, _CASES = _load(CORPUS_YAML)


def load_corpus(path: Path | None = None) -> list[CorpusCase]:
    if path is None:
        return list(_CASES)
    return _load(path)[1]
