import shutil

import pytest

from agent_perimeter.transport.stdio import (
    SECCOMP_PROFILE,
    LaunchSpec,
    StdioTransport,
    docker_args,
    two_phase_dockerfile,
)


def test_docker_args_enforce_every_containment_control() -> None:
    args = docker_args(LaunchSpec(image="python:3.12-slim", command=["python", "-c", "pass"]))
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--user 65534:65534" in joined
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--memory 256m" in joined
    assert "--pids-limit 128" in joined
    assert "--tmpfs /tmp" in joined
    assert "--ulimit nofile" in joined
    assert "HOME=/tmp" in joined
    assert " -v " not in joined, "no host mounts, ever"


def test_docker_default_seccomp_applies_unless_hardened_is_requested() -> None:
    """Docker's own default profile blocks the dangerous set (mount, ptrace,
    bpf, kexec, reboot, keyring calls) and is exercised across every
    architecture. The hand-written allowlist in seccomp.json is missing
    syscalls CPython needs (unlinkat, rt_sigsuspend, restart_syscall,
    membarrier, clock_nanosleep, socketpair, mremap, eventfd2, renameat2,
    ftruncate, getgroups, sched_getparam) and covers only x86_64 — so it is
    opt-in, never the default.
    """
    default = " ".join(docker_args(LaunchSpec(image="i", command=["c"])))
    assert "seccomp=" not in default

    hardened = " ".join(docker_args(LaunchSpec(image="i", command=["c"], hardened_seccomp=True)))
    assert f"seccomp={SECCOMP_PROFILE}" in hardened


def test_allow_network_is_explicit_and_off_by_default() -> None:
    default = " ".join(docker_args(LaunchSpec(image="i", command=["c"])))
    assert "--network none" in default

    permitted = " ".join(docker_args(LaunchSpec(image="i", command=["c"], allow_network=True)))
    assert "--network none" not in permitted


def test_zero_timeout_is_rejected() -> None:
    with pytest.raises(ValueError, match="timeout_s"):
        LaunchSpec(image="i", command=["c"], timeout_s=0)


def test_two_phase_dockerfile_installs_with_network_at_build_time() -> None:
    """npx -y <pkg> and uvx <pkg> both need network on every launch to
    resolve the package. Materialising the install into an image at build
    time — the one step that runs with network — is what lets the actual
    scan run every request with --network none."""
    dockerfile = two_phase_dockerfile(["npm", "install", "-g", "@scope/server"], "node:20-slim")
    assert dockerfile.startswith("FROM node:20-slim\n")
    assert "RUN npm install -g @scope/server" in dockerfile


_COUNTING_SERVER = (
    "import json, sys\n"
    "count = 0\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    count += 1\n"
    "    msg = json.loads(line)\n"
    "    reply = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {'count': count}}\n"
    "    print(json.dumps(reply), flush=True)\n"
)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")
def test_one_container_serves_a_multi_request_sequence() -> None:
    """The container is not restarted between calls, so state accumulates —
    exactly what a server-minted handle needs to survive across requests."""
    transport = StdioTransport(
        LaunchSpec(image="python:3.12-slim", command=["python3", "-c", _COUNTING_SERVER])
    )
    try:
        first = transport.request("ping")
        second = transport.request("ping")
        third = transport.request("ping")
    finally:
        transport.close()

    assert (first["count"], second["count"], third["count"]) == (1, 2, 3)
