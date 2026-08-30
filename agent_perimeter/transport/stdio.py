"""Containerised launcher for stdio MCP servers.

Scanning a stdio MCP server means executing an untrusted binary. Every launch
is confined: non-root, read-only rootfs, no network unless explicitly
required, tmpfs scratch, capability drop, no-new-privileges, memory/CPU/PID
caps, a hard wall-clock budget, and no host mounts under any circumstances.

One container runs for the *whole scan*, not one per JSON-RPC request. A
fresh container per call would discard whatever handle state the server
minted on an earlier request — 2026-07-28 requires cross-request state to be
an explicit server-minted handle, so a multi-step probe only works if every
call in it reaches the same process, and at eval-harness scale (~4,000
launches with MCPTox) a container per request is not runnable in CI either.
Requests are newline-delimited JSON-RPC framed over a persistent
stdin/stdout pipe; the container is torn down once, at the end of the scan.

Docker's *default* seccomp profile is applied unless `hardened_seccomp=True`
is set — see `seccomp.json`'s own note on why the hand-written allowlist is
opt-in rather than the default.

Every container is launched with a unique `--name` so it can be torn down by
the daemon (`docker kill <name>`) independently of the local `docker run` CLI
client process: killing that client does not stop a container the daemon
still owns (a hostile server that ignores stdin/EOF never exits on its own).
"""

from __future__ import annotations

import contextlib
import json
import shlex
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Literal

from agent_perimeter.transport.base import TransportError

SECCOMP_PROFILE = Path(__file__).parent / "seccomp.json"

# Generous cap for one JSON-RPC response line: bounds host memory against a
# server that floods stdout with a newline-free stream (I4). `readline()` on
# this text-mode stream takes a character count, not a byte count, so under
# UTF-8 the actual bound on host memory can be up to ~4x this many bytes —
# still a bound, just a looser one than the name alone would suggest.
_MAX_RESPONSE_LINE_CHARS = 512 * 1024


class ContainmentError(TransportError):
    """The sandboxed process breached or exceeded its confinement."""


def _bounded_tail(file: IO[str], limit: int = 400) -> str:
    """Read at most `limit` characters — never the whole file first.

    Used for the stderr excerpt embedded in an error message. `file.read()`
    followed by a `[:limit]` slice would materialize the entire (attacker-
    inflated) stream in host memory just to keep a few hundred characters
    of it — a hostile server can scale that to a host OOM.
    """
    try:
        file.seek(0)
        return file.read(limit)
    except (OSError, ValueError):
        return ""


def _reject_docker_flag_injection(value: str, field_name: str) -> None:
    """Fail closed on anything that could be parsed as a `docker` flag.

    `image` (and `base_image` for the two-phase build) are attacker-
    influenced — sourced from scanned targets' repo configs and registry
    manifests. Both are interpolated into a `docker run`/Dockerfile
    positionally, with nothing marking the end of options, so a value like
    `--privileged` or `--volume=/:/host` (or a newline smuggling an extra
    Dockerfile directive) would be consumed as a flag rather than as the
    bare reference it is supposed to be, unwinding the whole sandbox.
    """
    if not value or value.startswith("-") or any(c.isspace() for c in value):
        msg = f"{field_name} must be a bare image reference, not a docker flag"
        raise ValueError(msg)


@dataclass(frozen=True)
class LaunchSpec:
    image: str
    command: list[str]
    timeout_s: int = 300  # hard wall-clock budget for the whole scan, not one request
    allow_network: bool = False
    memory: str = "256m"
    cpus: str = "0.5"
    env: dict[str, str] = field(default_factory=dict)
    hardened_seccomp: bool = False  # opt in to the hand-written allowlist; default is Docker's own
    launch_phase: Literal["direct", "two_phase_build"] = "direct"
    """Which launch path produced `image` — recorded so a scan can report
    which targets needed the npx/uvx two-phase build (see
    `build_two_phase_image` below and revision §7.3)."""

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            msg = "timeout_s must be greater than zero"
            raise ValueError(msg)
        _reject_docker_flag_injection(self.image, "image")


def docker_args(spec: LaunchSpec, name: str | None = None) -> list[str]:
    """Build the `docker run` argument list. No host mounts are ever emitted.

    `name` gives the container a stable identity (defaults to a fresh
    `ap-<uuid4>`) so the caller can `docker kill <name>` it directly on the
    daemon — see the module docstring for why that matters.
    """
    container_name = name or f"ap-{uuid.uuid4()}"
    args = [
        "docker",
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--user",
        "65534:65534",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 -- Docker CLI flag value, not a temp-file path
        "--env",
        "HOME=/tmp",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        spec.memory,
        "--memory-swap",
        spec.memory,  # pin swap == memory; Docker's 2x default is not "no swap"
        "--cpus",
        spec.cpus,
        "--pids-limit",
        "128",
        "--ulimit",
        "nofile=1024:1024",
    ]
    if spec.hardened_seccomp:
        args += ["--security-opt", f"seccomp={SECCOMP_PROFILE}"]
    if not spec.allow_network:
        args += ["--network", "none"]
    for key, value in spec.env.items():
        args += ["--env", f"{key}={value}"]
    args.append(spec.image)
    args += spec.command
    return args


def two_phase_dockerfile(install_command: list[str], base_image: str) -> str:
    """A Dockerfile that fetches the package at build time, with network.

    `npx -y @scope/server` and `uvx some-server` both need network on every
    launch to resolve the package — the most common stdio invocation in the
    wild, and unscannable under `--network none` without this. `docker
    build` runs with the host's network regardless of the flags `docker run`
    will use later, so materialising the package here, once, is what lets
    every actual scan request run with `--network none`.
    """
    _reject_docker_flag_injection(base_image, "base_image")
    install = " ".join(shlex.quote(part) for part in install_command)
    return f"FROM {base_image}\nRUN {install}\n"


def build_two_phase_image(install_command: list[str], *, tag: str, base_image: str) -> str:
    """Build step only — runs WITH network. The resulting image needs none.

    Not exercised in CI without network access to the package registry.
    Tag the `LaunchSpec` that uses the resulting image with
    `launch_phase="two_phase_build"` so a scan can record which targets
    needed it — "we could not scan npx servers" is a coverage hole that
    should be visible, not silent (revision §7.3).
    """
    with tempfile.TemporaryDirectory() as build_dir:
        Path(build_dir, "Dockerfile").write_text(
            two_phase_dockerfile(install_command, base_image), encoding="utf-8"
        )
        subprocess.run(
            ["docker", "build", "-t", tag, build_dir],
            check=True,
            capture_output=True,
        )
    return tag


class StdioTransport:
    """One long-lived container for the whole scan.

    `docker run -i` is started once, on construction, under a unique
    `--name`. Every `request()` writes one newline-delimited JSON-RPC line
    to its stdin and reads lines back from its stdout — discarding anything
    that isn't the JSON-RPC object matching this call's `id` (a server may
    interleave notifications/progress messages with no `id`) — until it
    finds its response. A `threading.Timer` enforces the scan's hard
    wall-clock budget by killing the container on the daemon (`docker kill
    <name>`) *and* the local CLI client; a blocked read then sees EOF and
    raises `ContainmentError` rather than hanging forever.

    stderr is captured to a temp file rather than a pipe: a normal MCP
    server logs to stderr per convention, and an unread `PIPE` fills at
    ~64KB and deadlocks the container's write — a temp file never blocks.
    """

    def __init__(self, spec: LaunchSpec) -> None:
        self._spec = spec
        self._next_id = 1
        self._deadline_exceeded = False
        self._name = f"ap-{uuid.uuid4()}"
        self._stderr_file: IO[str] = tempfile.TemporaryFile(  # noqa: SIM115 -- held open for the transport's lifetime, not a short-lived read
            mode="w+", encoding="utf-8"
        )
        self._process: subprocess.Popen[str] = subprocess.Popen(
            docker_args(spec, name=self._name),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr_file,
            text=True,
            bufsize=1,
        )
        self._timer = threading.Timer(spec.timeout_s, self._on_deadline)
        self._timer.daemon = True
        self._timer.start()

    @property
    def launch_phase(self) -> str:
        return self._spec.launch_phase

    @property
    def container_name(self) -> str:
        return self._name

    def _kill_container(self) -> None:
        """Stop the container on the daemon, not just the local CLI client.

        `docker run`'s CLI process is a thin client; killing it does not
        stop a container the daemon still owns, so a hostile server that
        ignores stdin/EOF would otherwise keep running past the deadline.
        """
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["docker", "kill", self._name],
                capture_output=True,
                check=False,
                timeout=10,
            )

    def _on_deadline(self) -> None:
        self._deadline_exceeded = True
        self._kill_container()
        self._process.kill()

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if self._process.stdin is None or self._process.stdout is None:
            msg = "Container process has no stdio pipes."
            raise TransportError(msg)

        request_id = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        try:
            self._process.stdin.write(payload + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            if self._deadline_exceeded:
                msg = f"Container exceeded its {self._spec.timeout_s}s limit and was killed."
                raise ContainmentError(msg) from exc
            msg = f"Container stopped accepting input: {exc}"
            raise ContainmentError(msg) from exc

        while True:
            line = self._process.stdout.readline(_MAX_RESPONSE_LINE_CHARS)
            if not line:
                if self._deadline_exceeded:
                    msg = f"Container exceeded its {self._spec.timeout_s}s limit and was killed."
                    raise ContainmentError(msg)
                msg = (
                    f"No JSON-RPC response for {method}. Container exited "
                    f"(code {self._process.returncode}). "
                    f"stderr: {_bounded_tail(self._stderr_file)}"
                )
                raise TransportError(msg)

            if len(line) >= _MAX_RESPONSE_LINE_CHARS and not line.endswith("\n"):
                msg = (
                    f"Response line for {method} exceeded "
                    f"{_MAX_RESPONSE_LINE_CHARS} characters without a newline; refusing to "
                    "buffer further."
                )
                raise TransportError(msg)

            try:
                message = json.loads(line)
            except (ValueError, RecursionError) as exc:
                msg = f"Malformed JSON-RPC response for {method}: {exc}"
                raise TransportError(msg) from exc

            if not isinstance(message, dict):
                msg = f"JSON-RPC response for {method} was not a JSON object: {line.strip()!r}"
                raise TransportError(msg)

            if message.get("id") != request_id and "error" not in message:
                # A notification/progress message, or a stale response to an
                # earlier call — not this request's answer. Keep waiting.
                # An error frame is never discarded even with a mismatched
                # id: JSON-RPC 2.0 mandates `id: null` when the server
                # couldn't determine the request id, so a legitimate error
                # would otherwise be silently dropped, burning the scan's
                # whole wall-clock budget waiting for a match that never
                # comes (and losing the error `code` Task 8 depends on).
                continue

            if "error" in message:
                error = message["error"]
                code = error.get("code") if isinstance(error, dict) else None
                msg = f"Server returned an error for {method}: {error}"
                raise TransportError(msg, code=code if isinstance(code, int) else None)

            result = message.get("result", {})
            if not isinstance(result, dict):
                msg = f"JSON-RPC result for {method} was not a JSON object: {result!r}"
                raise TransportError(msg)
            return result

    def close(self) -> None:
        """Tear down the container. Cleanup, not reporting: never raises.

        `_kill_container()` is the guaranteed last resort if the process
        might still be alive — a `BrokenPipeError`/`OSError` closing stdin
        (the process may already have died) must never skip it, since the
        deadline timer is disarmed on the line above and nothing else will
        ever kill a still-running container on the daemon (I5). Any
        exception here is swallowed rather than raised, so it never masks
        a real error already propagating from the caller's `try/finally`.
        """
        self._timer.cancel()
        try:
            if self._process.poll() is None:
                if self._process.stdin is not None:
                    with contextlib.suppress(OSError):
                        self._process.stdin.close()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    self._process.wait(timeout=5)
                if self._process.poll() is None:
                    self._kill_container()
                    self._process.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        self._process.wait(timeout=5)
        finally:
            with contextlib.suppress(OSError):
                self._stderr_file.close()
