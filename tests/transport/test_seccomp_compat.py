import shutil
import subprocess
from pathlib import Path

import pytest

from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport

IMAGE = "agent-perimeter-fixture:test"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "servers"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    subprocess.run(
        ["docker", "build", "-t", IMAGE, str(FIXTURE)], check=True, capture_output=True
    )


@pytest.mark.parametrize("hardened_seccomp", [False, True])
def test_server_completes_a_request_under_the_profile(hardened_seccomp: bool) -> None:
    transport = StdioTransport(
        LaunchSpec(
            image=IMAGE,
            command=[],
            env={"AP_FIXTURE_REVISION": "2026-07-28", "AP_FIXTURE_FLAW": "none"},
            hardened_seccomp=hardened_seccomp,
        )
    )
    try:
        result = transport.request("server/discover")
    finally:
        transport.close()
    assert result["protocolVersions"] == ["2026-07-28"]
