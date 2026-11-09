"""The package works without the git checkout around it.

A wheel installs `agent_perimeter/` alone: no `tests/`, no `docs/`. Everything the CLI and the
Action import must load from that, which the rest of the suite can't see because it always runs
from a checkout. Found by examples/scan-reference-server.yml: `--html` crashed in an installed
copy because importing the report renderer read tests/fixtures/corpus.yaml.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import agent_perimeter

PACKAGE = Path(agent_perimeter.__file__).parent

_RENDER = """
from datetime import UTC, datetime
from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.feature import Revision
from agent_perimeter.report.html import render_report
from agent_perimeter.transport.revision import Fingerprint
fp = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset(),
    claim=Claim(value="2026-07-28", method=Method.DETERMINISTIC, derivation=Derivation.PROBE,
                observed_at=datetime(2026, 9, 1, tzinfo=UTC)),
)
html = render_report(findings=[], edges=[], fingerprint=fp, target="t",
                     skipped=[], notes=[], scores=[])
assert "<html" in html.lower(), html[:200]
import agent_perimeter.cli, agent_perimeter.action, agent_perimeter.report.sarif
print("ok")
"""


def test_cli_and_report_import_and_render_without_the_checkout(tmp_path: Path) -> None:
    shutil.copytree(
        PACKAGE, tmp_path / "agent_perimeter", ignore=shutil.ignore_patterns("__pycache__")
    )
    script = f"import sys; sys.path.insert(0, {str(tmp_path)!r})\n{_RENDER}"
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip().endswith("ok")
