"""A corpus case with `baseline_flaw` gives the drift check something to
compare against; without one the check must be skipped, not silent."""

from __future__ import annotations

from agent_perimeter.eval.corpus import CorpusCase, load_corpus
from agent_perimeter.eval.harness import run_case

DRIFT = "drift.description_drift"


def test_description_drift_fires_against_the_none_baseline() -> None:
    case = CorpusCase(id="t", revision="2026-07-28", flaw="drift_description", baseline_flaw="none")
    assert DRIFT in run_case(case)


def test_schema_drift_fires_against_the_none_baseline() -> None:
    case = CorpusCase(id="t", revision="2026-07-28", flaw="drift_schema", baseline_flaw="none")
    assert DRIFT in run_case(case)


def test_an_unchanged_server_does_not_fire() -> None:
    case = CorpusCase(id="t", revision="2026-07-28", flaw="none", baseline_flaw="none")
    assert DRIFT not in run_case(case)


def test_without_a_baseline_the_check_does_not_fire() -> None:
    case = CorpusCase(id="t", revision="2026-07-28", flaw="drift_description")
    assert DRIFT not in run_case(case)


def test_the_shipped_corpus_labels_drift() -> None:
    cases = {c.id: c for c in load_corpus()}
    assert cases["drift_description"].expect_findings == (DRIFT,)
    assert cases["drift_schema"].expect_findings == (DRIFT,)
    assert cases["drift_none_control"].expect_clean == (DRIFT,)
