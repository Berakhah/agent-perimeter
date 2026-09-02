# agent_perimeter/eval/run.py
"""Run the evaluation and rewrite the published table.

Runs in CI on every commit, so the published precision and recall cannot drift
from the code that produced them.
"""

from __future__ import annotations

import os
from pathlib import Path

from agent_perimeter.eval.corpus import CORPUS_VERSION, CorpusCase, load_corpus
from agent_perimeter.eval.harness import run_case
from agent_perimeter.eval.mcptox import (
    MCPTOX_REUSE_NOTE,
    POISON_CHECKS,
    POISON_DETECTED,
    load_mcptox,
)
from agent_perimeter.eval.score import CheckScore, render_table, score

START = "<!-- EVAL:START -->"
END = "<!-- EVAL:END -->"


def _observe(cases: list[CorpusCase]) -> dict[str, set[str]]:
    """Run each case through the real, in-process harness (Task 11: the same
    path a live scan runs, not one container per request).

    A poisoned MCPTox case is labelled with the synthetic POISON_DETECTED id
    rather than requiring every individual poisoning check to fire (§4.4):
    if any check in POISON_CHECKS fired, POISON_DETECTED is added to that
    case's observed set. Scoped to MCPTox cases only (id prefix "mcptox:") --
    descriptions.imperative_injection and .unicode_anomaly are each also the
    real, dedicated positive for their own local corpus case, so applying
    this label unconditionally would score those two local cases a false
    positive against a label that has nothing to do with them.
    """
    observed: dict[str, set[str]] = {}
    for case in cases:
        fired = run_case(case)
        if case.id.startswith("mcptox:") and fired & set(POISON_CHECKS):
            fired = fired | {POISON_DETECTED}
        observed[case.id] = fired
    return observed


def run_evaluation(*, include_mcptox: bool = True) -> tuple[list[CheckScore], str]:
    cases = load_corpus()
    provenance_lines = [
        f"Local corpus: `tests/fixtures/corpus.yaml` version {CORPUS_VERSION}, {len(cases)} cases.",
    ]

    mcptox_path = os.environ.get("AP_MCPTOX_PATH")
    if include_mcptox and mcptox_path and Path(mcptox_path).exists():
        mcptox_cases = load_mcptox(Path(mcptox_path))
        cases = cases + mcptox_cases
        provenance_lines.append(f"MCPTox: {len(mcptox_cases)} samples. {MCPTOX_REUSE_NOTE}")
    else:
        provenance_lines.append(
            "MCPTox: not run (dataset not present; set AP_MCPTOX_PATH to include it)."
        )

    return score(_observe(cases), cases), "\n\n".join(provenance_lines)


def write_methodology_table(scores: list[CheckScore], provenance: str, path: Path) -> None:
    body = f"{START}\n\n{provenance}\n\n{render_table(scores)}\n\n{END}"
    text = path.read_text(encoding="utf-8")
    head, _, rest = text.partition(START)
    _, _, tail = rest.partition(END)
    path.write_text(f"{head}{body}{tail}", encoding="utf-8")


if __name__ == "__main__":
    import sys

    scores, provenance = run_evaluation()
    if "--write" in sys.argv:
        write_methodology_table(scores, provenance, Path(sys.argv[sys.argv.index("--write") + 1]))
    else:
        print(render_table(scores))
