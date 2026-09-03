from pathlib import Path

from agent_perimeter.eval.run import run_evaluation, write_methodology_table


def test_evaluation_runs_over_the_local_corpus() -> None:
    scores, provenance = run_evaluation(include_mcptox=False)
    assert scores
    assert "corpus.yaml" in provenance


def test_provenance_records_that_mcptox_did_not_run() -> None:
    _, provenance = run_evaluation(include_mcptox=False)
    assert "MCPTox: not run" in provenance


def test_poisoning_detected_label_never_leaks_onto_local_corpus_cases() -> None:
    """POISON_CHECKS (descriptions.imperative_injection, .unicode_anomaly)
    are also each the real, dedicated positive for their own local corpus
    case -- _observe() must only synthesise mcptox.poisoning_detected for
    cases that actually came from MCPTox, or those two local cases score a
    false positive against a label that has nothing to do with them."""
    scores, _ = run_evaluation(include_mcptox=False)
    assert not any(s.check_id == "mcptox.poisoning_detected" for s in scores)


def test_methodology_table_is_written_between_markers(tmp_path: Path) -> None:
    path = tmp_path / "methodology.md"
    path.write_text("# Methodology\n\n<!-- EVAL:START -->\nold\n<!-- EVAL:END -->\n\ntail\n")
    scores, provenance = run_evaluation(include_mcptox=False)
    write_methodology_table(scores, provenance, path)
    written = path.read_text()
    assert "old" not in written
    assert "| Check |" in written
    assert written.endswith("tail\n")


def test_rewriting_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "methodology.md"
    path.write_text("<!-- EVAL:START -->\n<!-- EVAL:END -->\n")
    scores, provenance = run_evaluation(include_mcptox=False)
    write_methodology_table(scores, provenance, path)
    first = path.read_text()
    write_methodology_table(scores, provenance, path)
    assert path.read_text() == first
