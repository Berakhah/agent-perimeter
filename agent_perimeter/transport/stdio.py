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
"""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from agent_perimeter.transport.base import TransportError

SECCOMP_PROFILE = Path(__file__).parent / "seccomp.json"


class ContainmentError(TransportError):
    """The sandboxed process breached or exceeded its confinement."""


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


def docker_args(spec: LaunchSpec) -> list[str]:
    """Build the `docker run` argument list. No host mounts are ever emitted."""
    args = [
        "docker", "run", "--rm", "-i",
        "--user", "65534:65534",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--env", "HOME=/tmp",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--pids-limit", "128",
        "--ulimit", "nofile=1024:1024",
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

    `docker run -i` is started once, on construction. Every `request()`
    writes one newline-delimited JSON-RPC line to its stdin and reads one
    back from its stdout — the framing the fixture, and every real stdio
    server, already speaks. A `threading.Timer` enforces the scan's hard
    wall-clock budget by killing the process; a blocked read then sees EOF
    and raises `ContainmentError` rather than hanging forever.
    """

    def __init__(self, spec: LaunchSpec) -> None:
        self._spec = spec
        self._next_id = 1
        self._deadline_exceeded = False
        self._process: subprocess.Popen[str] = subprocess.Popen(
            docker_args(spec),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._timer = threading.Timer(spec.timeout_s, self._on_deadline)
        self._timer.daemon = True
        self._timer.start()

    @property
    def launch_phase(self) -> str:
        return self._spec.launch_phase

    def _on_deadline(self) -> None:
        self._deadline_exceeded = True
        self._process.kill()

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
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
            msg = f"Container stopped accepting input: {exc}"
            raise ContainmentError(msg) from exc

        line = self._process.stdout.readline()
        if not line:
            if self._deadline_exceeded:
                msg = f"Container exceeded its {self._spec.timeout_s}s limit and was killed."
                raise ContainmentError(msg)
            stderr = self._process.stderr.read()[:400] if self._process.stderr else ""
            msg = (
                f"No JSON-RPC response for {method}. Container exited "
                f"(code {self._process.returncode}). stderr: {stderr}"
            )
            raise TransportError(msg)

        message = json.loads(line)
        if "error" in message:
            error = message["error"]
            code = error.get("code") if isinstance(error, dict) else None
            msg = f"Server returned an error for {method}: {error}"
            raise TransportError(msg, code=code if isinstance(code, int) else None)
        result: dict[str, object] = message.get("result", {})
        return result

    def close(self) -> None:
        self._timer.cancel()
        if self._process.poll() is None:
            if self._process.stdin is not None:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
