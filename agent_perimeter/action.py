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

import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


def read_sarif(path: Path) -> dict[str, Any] | None:
    """The SARIF the CLI wrote, or ``None`` if it wrote none."""
    if not path.is_file():
        return None
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def sarif_results(sarif: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if sarif is None:
        return []
    runs = sarif.get("runs") or []
    if not runs:
        return []
    results: list[dict[str, Any]] = list(runs[0].get("results") or [])
    return results


def drift_verdict(sarif: Mapping[str, Any] | None, *, first_run: bool) -> str:
    """``none`` on a first run; otherwise whether the drift check fired.

    Read from the SARIF, not the exit code, so ``fail-on-drift: false``
    still yields a usable signal.
    """
    if first_run:
        return "none"
    drifted = any(r.get("ruleId") == DRIFT_CHECK_ID for r in sarif_results(sarif))
    return "true" if drifted else "false"


def write_outputs(path: Path | None, outputs: Mapping[str, str]) -> None:
    lines = [f"{key}={value}" for key, value in outputs.items()]
    if path is None:
        print("::notice::GITHUB_OUTPUT is not set; printing outputs instead.")
        print("\n".join(lines))
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_summary(path: Path | None, text: str) -> None:
    if path is None:
        print("::notice::GITHUB_STEP_SUMMARY is not set; printing the summary instead.")
        print(text)
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def render_summary(
    inputs: Inputs, sarif: Mapping[str, Any] | None, *, first_run: bool, rc: int
) -> str:
    """Counts, ids and severities only -- never a message body (rule 5)."""
    results = sarif_results(sarif)
    props: Mapping[str, Any] = {}
    if sarif is not None and sarif.get("runs"):
        props = sarif["runs"][0].get("properties") or {}
    by_level: dict[str, int] = {}
    for result in results:
        level = str(result.get("level", "none"))
        by_level[level] = by_level.get(level, 0) + 1
    verdict = drift_verdict(sarif, first_run=first_run)
    drifted = sum(1 for r in results if r.get("ruleId") == DRIFT_CHECK_ID)

    rows = [
        "## Agent Perimeter",
        "",
        "| | |",
        "|---|---|",
        f"| Target | `{inputs.target or inputs.image}` |",
        f"| Mode | {inputs.mode or 'passive'} |",
        f"| Revision claimed | {props.get('revision_claimed') or 'unknown'} |",
        f"| Findings | {len(results)} |",
        f"| Drift | {verdict} |",
        f"| Exit code | {rc} |",
    ]
    if by_level:
        rows += ["", "| Severity | Count |", "|---|---|"]
        rows += [f"| {level} | {count} |" for level, count in sorted(by_level.items())]
    if first_run:
        rows += [
            "",
            f"Baseline written to `{inputs.baseline}`. Commit it to arm the drift gate.",
        ]
    elif verdict == "true":
        rows += [
            "",
            f"Drift gate tripped: {drifted} tool(s) changed since the baseline. "
            f"Review the diff with `agent-perimeter drift {shlex.quote(inputs.baseline)} "
            f"{shlex.quote(inputs.snapshot)}`; commit the new snapshot as the baseline "
            "to approve.",
        ]
    return "\n".join(rows)


def _subprocess_run(argv: list[str]) -> int:  # pragma: no cover -- the self-test workflow runs it
    return subprocess.run(argv, check=False).returncode


def main(
    *,
    environ: Mapping[str, str] | None = None,
    run: Callable[[list[str]], int] | None = None,
) -> int:
    """Entry point. Returns the exit code (0 ok, 2 usage/missing artifact, 3 drift)."""
    env = os.environ if environ is None else environ
    execute = _subprocess_run if run is None else run

    try:
        inputs = read_inputs(env)
    except InputError as exc:
        print(str(exc))
        return 2

    gh_output = Path(env["GITHUB_OUTPUT"]) if env.get("GITHUB_OUTPUT") else None
    gh_summary = Path(env["GITHUB_STEP_SUMMARY"]) if env.get("GITHUB_STEP_SUMMARY") else None

    first_run = not Path(inputs.baseline).is_file()
    # The CLI writes with write_text and does not create directories; the
    # defaults live under .agent-perimeter/, which a fresh checkout lacks.
    for target_path in (inputs.baseline, inputs.snapshot, inputs.sarif, inputs.html):
        if target_path:
            Path(target_path).parent.mkdir(parents=True, exist_ok=True)

    command = build_argv(inputs, first_run=first_run)
    print("Reproduction: " + reproduction_line(command), flush=True)
    rc = execute(command)

    sarif = read_sarif(Path(inputs.sarif))
    if rc == 0 and sarif is None:
        print(
            f"Scan exited 0 but wrote no SARIF at {inputs.sarif}. "
            "Check the `sarif` input points at a writable path."
        )
        rc = 2

    outputs: dict[str, str] = {}
    if sarif is not None:
        outputs["sarif-file"] = inputs.sarif
    outputs["snapshot-file"] = inputs.baseline if first_run else inputs.snapshot
    outputs["baseline-created"] = "true" if first_run else "false"
    outputs["drift"] = drift_verdict(sarif, first_run=first_run)
    outputs["finding-count"] = str(len(sarif_results(sarif)))
    write_outputs(gh_output, outputs)
    write_summary(gh_summary, render_summary(inputs, sarif, first_run=first_run, rc=rc))
    return rc


if __name__ == "__main__":  # pragma: no cover -- exercised by the self-test workflow
    sys.exit(main())
