import shutil
from pathlib import Path

import pytest

from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from tests.docker_build import build_image as build_docker_image

IMAGE = "agent-perimeter-fixture:test"
NODE_IMAGE = "agent-perimeter-fixture-node:test"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "servers"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    build_docker_image(IMAGE, FIXTURE)
    build_docker_image(NODE_IMAGE, FIXTURE, dockerfile=FIXTURE / "Dockerfile.node")


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


def test_node_runtime_completes_a_request_under_the_hardened_profile() -> None:
    """hardened_seccomp defaults to True for every stdio launch (stdio.py),
    including npx-launched Node.js servers -- but seccomp.json's allowlist
    was built by tracing only the Python fixture. This is the regression
    proof: if Node needs a syscall the profile does not grant, it fails here
    in CI, instead of silently as "Container exited" on a real npx target.
    """
    transport = StdioTransport(LaunchSpec(image=NODE_IMAGE, command=[], hardened_seccomp=True))
    try:
        result = transport.request("server/discover")
    finally:
        transport.close()
    assert result["protocolVersions"] == ["2026-07-28"]
