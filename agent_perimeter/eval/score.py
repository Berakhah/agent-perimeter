"""Per-check precision and recall.

Per check class, never one headline scalar: a single number is what a
competitor quotes, a table of rows is what an engineer reads.

Undefined is not zero. A check with nothing predicted has undefined precision
and the table prints n/a, because printing 0.00 would say "this check is bad"
when the truth is "this check was not exercised".

Closed-world labelling (revision §4.1): every check defaults to expect_clean
on every case unless that case names it in expect_findings. A check firing on
a case that names it in neither list is a false positive, not an invisible
event -- the alternative silently drops most of what a real scan would
surface, and the published precision would not mean what a reader assumes.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_perimeter.eval.corpus import CorpusCase


@dataclass(frozen=True)
class CheckScore:
    check_id: str
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    n: int


def score(observed: dict[str, set[str]], cases: list[CorpusCase]) -> list[CheckScore]:
    """`observed` maps case id to the set of check ids that fired.

    Closed-world: a check is scored against *every* case, not only the cases
    that mention it. A case naming the check in expect_findings is a positive
    for it; every other case -- named in expect_clean or not named at all --
    is an implicit negative.
    """
    check_ids: set[str] = set()
    for case in cases:
        check_ids.update(case.expect_findings)
        check_ids.update(case.expect_clean)
    for fired_ids in observed.values():
        check_ids.update(fired_ids)

    scores: list[CheckScore] = []
    for check_id in sorted(check_ids):
        tp = fp = fn = n = 0
        for case in cases:
            fired = check_id in observed.get(case.id, set())
            n += 1
            if check_id in case.expect_findings:
                if fired:
                    tp += 1
                else:
                    fn += 1
            elif fired:
                # Closed-world default: not named as a positive means this
                # case expects the check to stay clean, whether or not it
                # was explicitly listed in expect_clean.
                fp += 1

        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        scores.append(
            CheckScore(
                check_id=check_id,
                tp=tp,
                fp=fp,
                fn=fn,
                precision=precision,
                recall=recall,
                n=n,
            )
        )
    return scores


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def render_table(scores: list[CheckScore]) -> str:
    lines = [
        "| Check | n | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for s in scores:
        lines.append(
            f"| `{s.check_id}` | {s.n} | {s.tp} | {s.fp} | {s.fn} | "
            f"{_fmt(s.precision)} | {_fmt(s.recall)} |"
        )
    return "\n".join(lines)
