import shutil
import subprocess
import time
from pathlib import Path

import pytest

from agent_perimeter.transport.stdio import (
    ContainmentError,
    LaunchSpec,
    StdioTransport,
    docker_args,
)

IMAGE = "agent-perimeter-hostile:test"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "hostile"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    subprocess.run(["docker", "build", "-t", IMAGE, str(FIXTURE)], check=True, capture_output=True)


def _run(mode: str, timeout_s: int = 30) -> subprocess.CompletedProcess[str]:
    spec = LaunchSpec(image=IMAGE, command=[], env={"AP_HOSTILE_MODE": mode}, timeout_s=timeout_s)
    return subprocess.run(
        docker_args(spec), capture_output=True, text=True, timeout=60, check=False
    )


def test_network_is_unreachable() -> None:
    assert "CONTAINED" in _run("network").stderr


def test_rootfs_is_read_only() -> None:
    assert "CONTAINED" in _run("rootfs_write").stderr


def test_process_does_not_run_as_root() -> None:
    assert "UID=65534" in _run("root").stderr


def test_memory_bomb_is_killed() -> None:
    """`returncode != 0` alone would also pass for a bad image, wrong
    command, or missing env — none of which prove the OOM killer actually
    fired. 137 is 128 + SIGKILL(9): the exit code a Linux container reports
    when the kernel's OOM killer sends it SIGKILL, confirmed against this
    fixture on this Docker daemon via `docker inspect -f
    '{{.State.OOMKilled}}'` (returns `true` alongside this exact exit code)."""
    assert _run("memory", timeout_s=60).returncode == 137


def test_hang_hits_the_hard_timeout() -> None:
    transport = StdioTransport(
        LaunchSpec(image=IMAGE, command=[], env={"AP_HOSTILE_MODE": "hang"}, timeout_s=5)
    )
    with pytest.raises(ContainmentError, match="exceeded its 5s limit"):
        transport.request("tools/list")


def test_hang_timeout_actually_kills_the_daemon_container() -> None:
    """Regression guard for a real sandbox-escape bug found in Task 4 review.

    An earlier version of the deadline handling raised ContainmentError while
    the container kept running on the Docker daemon — only the local `docker
    run` CLI client had been killed. Task 4 fixed this by naming the
    container and issuing `docker kill <name>` against the daemon. Asserting
    on the exception alone (as in test_hang_hits_the_hard_timeout above)
    cannot catch a regression of that class, so this test independently asks
    the daemon — via `docker inspect` on the container's actual name — whether
    the container is genuinely gone, not just that the client raised.
    """
    transport = StdioTransport(
        LaunchSpec(image=IMAGE, command=[], env={"AP_HOSTILE_MODE": "hang"}, timeout_s=5)
    )
    container_name = transport.container_name

    with pytest.raises(ContainmentError, match="exceeded its 5s limit"):
        transport.request("tools/list")

    # The container was launched with --rm, so once the daemon truly kills
    # it, `docker inspect` should stop finding it at all. Poll briefly: kill
    # and removal are two daemon-side steps and may not be atomic.
    deadline = time.monotonic() + 10
    inspect: subprocess.CompletedProcess[str]
    while True:
        inspect = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True,
            text=True,
            check=False,
        )
        container_gone = inspect.returncode != 0
        container_stopped = inspect.stdout.strip() == "false"
        if container_gone or container_stopped or time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    assert container_gone or container_stopped, (
        f"container {container_name!r} is still reported running by the "
        f"Docker daemon after the hard timeout fired: {inspect.stdout!r}"
    )
