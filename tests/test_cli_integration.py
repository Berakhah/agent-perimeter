"""End-to-end CLI test against the real fixture image — nothing stubbed.

All of tests/test_cli.py's tests stub out `fingerprint()`, so the CLI's
actual StdioTransport construction path in `_build_transport` — including
the `--env` option threaded through to `LaunchSpec.env` — has no coverage
from a real run. This proves the Week 1 completion gate directly: `agent-
perimeter scan --target ...` fingerprints the fixture server at both
`2025-11-25` and `2026-07-28`, selected via `--env AP_FIXTURE_REVISION=...`
since the CLI has no other way to steer a stdio target's revision.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_perimeter.cli import app

IMAGE = "agent-perimeter-fixture:test"
FIXTURE = Path(__file__).parent / "fixtures" / "servers"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")

runner = CliRunner()


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    subprocess.run(["docker", "build", "-t", IMAGE, str(FIXTURE)], check=True, capture_output=True)


@pytest.mark.parametrize("revision", ["2025-11-25", "2026-07-28"])
def test_scan_cli_fingerprints_the_real_fixture_at_each_revision(revision: str) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "",
            "--image",
            IMAGE,
            "--env",
            f"AP_FIXTURE_REVISION={revision}",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert revision in result.stdout
