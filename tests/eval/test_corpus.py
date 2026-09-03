from collections import Counter

from agent_perimeter.eval.corpus import CORPUS_VERSION, load_corpus


def test_corpus_loads_and_is_versioned() -> None:
    cases = load_corpus()
    assert cases
    assert CORPUS_VERSION


def test_case_ids_are_unique() -> None:
    ids = [c.id for c in load_corpus()]
    assert len(ids) == len(set(ids))


def test_every_case_asserts_something() -> None:
    for case in load_corpus():
        assert case.expect_findings or case.expect_clean, case.id


def test_corpus_contains_clean_controls() -> None:
    """Precision is meaningless without cases that should produce nothing."""
    controls = [c for c in load_corpus() if c.expect_clean]
    assert len(controls) >= len(load_corpus()) / 3


def test_positive_and_control_cases_are_roughly_balanced() -> None:
    kinds = Counter("positive" if c.expect_findings else "control" for c in load_corpus())
    assert kinds["control"] >= kinds["positive"] * 0.5


def test_a_legacy_control_exists_so_skips_are_measured() -> None:
    assert any(c.revision == "2025-11-25" for c in load_corpus())
