from agent_perimeter.eval.corpus import CorpusCase
from agent_perimeter.eval.score import render_table, score

CASES = [
    CorpusCase(id="pos", revision="2026-07-28", flaw="x", expect_findings=("chk.a",)),
    CorpusCase(id="neg", revision="2026-07-28", flaw="none", expect_clean=("chk.a",)),
]


def test_perfect_detector_scores_one() -> None:
    observed = {"pos": {"chk.a"}, "neg": set()}
    result = {s.check_id: s for s in score(observed, CASES)}["chk.a"]
    assert result.tp == 1 and result.fp == 0 and result.fn == 0
    assert result.precision == 1.0 and result.recall == 1.0


def test_false_positive_lowers_precision() -> None:
    observed = {"pos": {"chk.a"}, "neg": {"chk.a"}}
    result = {s.check_id: s for s in score(observed, CASES)}["chk.a"]
    assert result.fp == 1
    assert result.precision == 0.5
    assert result.recall == 1.0


def test_missed_detection_lowers_recall() -> None:
    observed: dict[str, set[str]] = {"pos": set(), "neg": set()}
    result = {s.check_id: s for s in score(observed, CASES)}["chk.a"]
    assert result.fn == 1
    assert result.recall == 0.0


def test_precision_is_none_when_nothing_was_predicted() -> None:
    observed: dict[str, set[str]] = {"pos": set(), "neg": set()}
    result = {s.check_id: s for s in score(observed, CASES)}["chk.a"]
    assert result.precision is None


def test_table_renders_undefined_rather_than_zero() -> None:
    observed: dict[str, set[str]] = {"pos": set(), "neg": set()}
    table = render_table(score(observed, CASES))
    assert "n/a" in table
    assert "0.00 | 0.00" not in table


def test_table_has_one_row_per_check() -> None:
    observed = {"pos": {"chk.a"}, "neg": set()}
    rows = [line for line in render_table(score(observed, CASES)).splitlines() if "chk." in line]
    assert len(rows) == 1


def test_check_firing_on_an_unlisted_case_counts_as_a_false_positive() -> None:
    """Closed-world labelling (revision §4.1): a case that names neither
    `expect_findings` nor `expect_clean` for a check is an implicit
    expect_clean for it. Before this fix such a firing was invisible --
    neither TP, FP nor FN."""
    cases = [
        CorpusCase(id="unrelated", revision="2026-07-28", flaw="y", expect_findings=("chk.b",)),
    ]
    observed = {"unrelated": {"chk.a"}}
    result = {s.check_id: s for s in score(observed, cases)}["chk.a"]
    assert result.fp == 1
    assert result.precision == 0.0
