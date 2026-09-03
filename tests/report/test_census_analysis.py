"""Tests for analysis/census_analysis.py - a loose top-level script, not part
of the `agent_perimeter` package (deliberately: it must never import it, see
that module's own docstring), so it's loaded here from its file path rather
than a normal package import.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from agent_perimeter.report.census_report import export_raw
from tests.report.factories import census_fixture

_SCRIPT = Path(__file__).parents[2] / "analysis" / "census_analysis.py"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("census_analysis", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


census_analysis = _load_script()


def test_check_succeeds_from_the_csv_alone_with_no_summary_sidecar(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The completion gate's wording is 'from the published CSV alone' - the
    script must run to completion (and report success) with nothing else
    present, not require a sidecar it was never handed."""
    run, records = census_fixture(
        supports=2, does_not_support=1, unknown=1, probe_supports=1, probe_unknown=1
    )
    csv_path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary_path = csv_path.with_name(census_analysis.SUMMARY_NAME)
    assert summary_path.is_file()
    summary_path.unlink()

    ok = census_analysis.check(csv_path, summary_path)
    assert ok is True


def test_main_exits_zero_from_the_csv_alone(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    run, records = census_fixture(supports=3, does_not_support=0, unknown=0)
    csv_path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    csv_path.with_name(census_analysis.SUMMARY_NAME).unlink()

    exit_code = census_analysis.main(["census_analysis.py", str(csv_path)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "artifact.pooled.supports" in out


def test_check_matches_the_summary_sidecar_when_present(tmp_path) -> None:  # type: ignore[no-untyped-def]
    run, records = census_fixture(
        supports=2, does_not_support=1, unknown=1, probe_supports=2, probe_unknown=3
    )
    csv_path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary_path = csv_path.with_name(census_analysis.SUMMARY_NAME)
    assert summary_path.is_file()

    assert census_analysis.check(csv_path, summary_path) is True


def test_check_reports_a_real_mismatch_instead_of_papering_over_it(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A published report and its raw data disagreeing is exactly the
    failure this script exists to catch - it must fail loudly, not quietly
    report success."""
    run, records = census_fixture(supports=2, does_not_support=1, unknown=0)
    csv_path = export_raw(run, records, salt=b"test-salt", out=tmp_path)
    summary_path = csv_path.with_name(census_analysis.SUMMARY_NAME)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["artifact"]["pooled"]["supports"] = 999
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    assert census_analysis.check(csv_path, summary_path) is False
