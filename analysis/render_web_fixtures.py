"""Render `web/tests/fixtures/report.html` and `.../census.html` from the
real, pure Jinja renderers (`report.html.py::render_report`,
`report.census_report.py::render_census`), using this project's existing
sample-data factories.

Task 16 pre-flight ruling 1: the brief's own `pretest` command
(`agent-perimeter scan --target fixture://mixed --html ...`) doesn't work --
`fixture://` isn't a target scheme `scan_runner.build_transport` recognises,
and it never will be; a real scan is unnecessary and less deterministic than
just calling the renderers directly with representative data. This script is
that direct call. It is `web/package.json`'s `pretest` step -- run before
every Playwright invocation, never committed output (`web/tests/fixtures/
report.html` and `census.html` are gitignored, generated fresh every run so
they can never drift from the emitter):

    uv run python analysis/render_web_fixtures.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_perimeter.eval.score import CheckScore  # noqa: E402
from agent_perimeter.report.census_report import render_census  # noqa: E402
from agent_perimeter.report.html import render_report  # noqa: E402
from tests.report.factories import census_fixture  # noqa: E402
from tests.report.test_html import EDGE, FINDING, FINGERPRINT  # noqa: E402

OUT = ROOT / "web" / "tests" / "fixtures"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    report_html = render_report(
        findings=[FINDING],
        edges=[EDGE],
        fingerprint=FINGERPRINT,
        target="https://mcp.example.test/rpc",
        skipped=[],
        scores=[CheckScore("revision.cache_scope", 4, 1, 0, 0.8, 1.0, 5)],
    )
    report_path = OUT / "report.html"
    report_path.write_text(report_html, encoding="utf-8")

    # Both strata populated (some live-discover data) so the fixture is
    # representative of a real publication, not just the empty-Tier-3 case
    # already covered by tests/report/test_census_report.py directly.
    run, records = census_fixture(
        supports=5, does_not_support=3, unknown=2, probe_supports=6, probe_unknown=3
    )
    census_html = render_census(run, records)
    census_path = OUT / "census.html"
    census_path.write_text(census_html, encoding="utf-8")

    print(f"wrote {report_path}")
    print(f"wrote {census_path}")


if __name__ == "__main__":
    main()
