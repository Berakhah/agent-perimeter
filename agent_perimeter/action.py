"""GitHub Action entry point -- ``python -m agent_perimeter.action``.

Spec: docs/superpowers/specs/2026-09-16-github-action-design.md.

Everything here is glue around the unchanged ``agent-perimeter scan`` CLI:
read the ``INPUT_*`` variables GitHub sets for an action, decide whether
this is a first run (no baseline file yet) or a gate run, print and run
the exact argv a sceptic could paste, then turn the SARIF the CLI wrote
into step outputs and a job summary. It never calls a model, never opens
a network connection itself, and never writes a scope file.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# Mirrors agent_perimeter/checks/drift/description_drift.py:CHECK.id.
# Importing the check package into this glue module would pull the whole
# checks tree in for one string; tests/action/test_action.py pins equality.
DRIFT_CHECK_ID = "drift.description_drift"

INPUT_NAMES: tuple[str, ...] = (
    "target",
    "mode",
    "scope-file",
    "image",
    "env",
    "only",
    "baseline",
    "snapshot",
    "fail-on-drift",
    "sarif",
    "html",
    "upload-sarif",
)


class InputError(ValueError):
    """An input the action cannot proceed with. The message is user-facing."""


@dataclass(frozen=True)
class Inputs:
    target: str
    mode: str
    scope_file: str
    image: str
    env: tuple[str, ...]
    only: str
    baseline: str
    snapshot: str
    fail_on_drift: bool
    sarif: str
    html: str
    upload_sarif: bool


def _get(environ: Mapping[str, str], name: str) -> str:
    return environ.get(f"INPUT_{name.upper()}", "").strip()


def _flag(environ: Mapping[str, str], name: str) -> bool:
    raw = _get(environ, name).lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise InputError(f"`{name}` must be `true` or `false`; got {raw!r}.")


def read_inputs(environ: Mapping[str, str]) -> Inputs:
    """Build ``Inputs`` from GitHub's ``INPUT_<NAME>`` variables.

    A missing variable is the same as an empty one. ``target`` may be empty
    only when ``image`` is set: the CLI then runs the image's own entrypoint
    as the server (``tests/test_cli_integration.py`` relies on the same).
    """
    target = _get(environ, "target")
    image = _get(environ, "image")
    if not target and not image:
        raise InputError(
            "Set the `target` input to a URL or a stdio command, or set `image` "
            "to a container image whose entrypoint is the server."
        )
    env_lines = tuple(line.strip() for line in _get(environ, "env").splitlines() if line.strip())
    return Inputs(
        target=target,
        mode=_get(environ, "mode"),
        scope_file=_get(environ, "scope-file"),
        image=image,
        env=env_lines,
        only=_get(environ, "only"),
        baseline=_get(environ, "baseline"),
        snapshot=_get(environ, "snapshot"),
        fail_on_drift=_flag(environ, "fail-on-drift"),
        sarif=_get(environ, "sarif"),
        html=_get(environ, "html"),
        upload_sarif=_flag(environ, "upload-sarif"),
    )


def build_argv(inputs: Inputs, *, first_run: bool) -> list[str]:
    """The exact ``agent-perimeter scan`` command the action runs.

    First run (no baseline on disk): write this scan's snapshot *to the
    baseline path* and do not gate. Gate run: diff against the baseline,
    write the snapshot to ``snapshot``, and add ``--fail-on-drift`` when
    asked. Optional flags appear only when their input is non-empty --
    including ``--scope-file`` (rule 1: the CLI refuses active mode
    without one; the action never fills it in).
    """
    argv = ["agent-perimeter", "scan", "--target", inputs.target]
    if inputs.mode:
        argv += ["--mode", inputs.mode]
    if inputs.scope_file:
        argv += ["--scope-file", inputs.scope_file]
    if inputs.image:
        argv += ["--image", inputs.image]
    for pair in inputs.env:
        argv += ["--env", pair]
    if inputs.only:
        argv += ["--only", inputs.only]
    if inputs.html:
        argv += ["--html", inputs.html]
    argv += ["--sarif", inputs.sarif]
    if first_run:
        argv += ["--snapshot", inputs.baseline]
    else:
        argv += ["--baseline", inputs.baseline, "--snapshot", inputs.snapshot]
        if inputs.fail_on_drift:
            argv.append("--fail-on-drift")
    return argv


def reproduction_line(argv: Sequence[str]) -> str:
    """``shlex.join(argv)`` with every ``--env KEY=VALUE`` value masked.

    Rule 3: env values are how a consumer passes credentials to a stdio
    server; they must never land in a job log. Malformed tokens without
    '=' are masked entirely as '***' rather than appearing unmasked.
    """
    masked: list[str] = []
    previous = ""
    for part in argv:
        if previous == "--env":
            if "=" in part:
                key, _, _ = part.partition("=")
                masked.append(f"{key}=***")
            else:
                masked.append("***")
        else:
            masked.append(part)
        previous = part
    return shlex.join(masked)
