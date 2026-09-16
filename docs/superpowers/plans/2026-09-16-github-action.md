# GitHub Action Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `uses: Berakhah/agent-perimeter@v1` — a composite GitHub Action that scans an MCP target with the existing CLI, uploads SARIF to code scanning, and fails the job (exit 3) when the server's tools drift from a baseline snapshot committed in the consumer's repo.

**Architecture:** `agent_perimeter/action.py` is a small, fully unit-tested module run as `python -m agent_perimeter.action`: it reads `INPUT_*` env vars, decides first-run vs. gate-run from whether the baseline file exists, assembles and prints the exact `agent-perimeter scan …` argv, runs it as a subprocess, reads the SARIF the CLI wrote, and writes `$GITHUB_OUTPUT` / `$GITHUB_STEP_SUMMARY`. `action.yml` at the repo root is three steps of glue (setup-uv + install from `github.action_path`, run the module, `upload-sarif`). A self-test workflow exercises the action against the stdio fixture image on `ubuntu-latest`. Nothing in `cli.py`, `scan_runner`, the checks, or the API changes.

**Tech Stack:** Python 3.12 stdlib only (`dataclasses`, `subprocess`, `shlex`, `json`, `pathlib`); PyYAML (already a dependency) in tests; GitHub Actions composite syntax; pytest.

**Spec:** `docs/superpowers/specs/2026-09-16-github-action-design.md`. Read it first; every task below cites its section.

## Global Constraints

- `mypy --strict` clean on `agent_perimeter/`; `ruff check` and `ruff format --check` clean (line length 100, rules `E F I UP B SIM S`).
- TDD: every task writes the failing test first, runs it red, then implements. No exceptions.
- Coverage floor 75% overall; `agent_perimeter/action.py` targets 100% (it is ~150 lines of branches).
- Copy rules: errors state what happened and what to do, no apology. Never "You're secure!".
- Rule 1: the action never creates, templates, or defaults a scope file. It passes `scope-file` through verbatim or not at all.
- Rule 3: `env` input values never appear in the printed reproduction line (`--env KEY=***`) or the job summary.
- Rule 5: the job summary shows counts, check ids, severities. Never a tool description or finding message body.
- No new runtime dependency. No hardcoded model names. No secrets in fixtures or workflows.
- Exit codes unchanged from the CLI: `0` ok · `2` refused/usage/missing artifact · `3` drift gate tripped.
- Pinned action refs only: `astral-sh/setup-uv@v10.1.0`, `github/codeql-action/upload-sarif@v4.38.0` (both verified current on 2026-09-16 via `gh api`). Never a floating `@v4`.
- Run tools from the venv: `.venv/Scripts/pytest`, `.venv/Scripts/ruff`, `.venv/Scripts/mypy` (Windows Git Bash). On CI, `uv run …` is equivalent.
- Lint/type gate, run at the end of every task: `.venv/Scripts/ruff check . --exclude .claude && .venv/Scripts/ruff format . --exclude .claude && .venv/Scripts/mypy --strict agent_perimeter` — referred to below as **the gate**.
- Commit after every task with the trailer `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- Work on branch `github-action` (created in Task 1 via the using-git-worktrees skill or `git switch -c github-action`).

## File map

| File | Responsibility | Task |
|---|---|---|
| `agent_perimeter/action.py` | `Inputs` dataclass, `read_inputs`, `build_argv`, `reproduction_line`, `read_sarif`, `sarif_results`, `drift_verdict`, `write_outputs`, `write_summary`, `render_summary`, `main`; `if __name__ == "__main__"` so `python -m agent_perimeter.action` works | 1, 2 |
| `tests/action/__init__.py` | package marker | 1 |
| `tests/action/test_action.py` | unit tests for every branch of `action.py` | 1, 2 |
| `action.yml` | composite action manifest (spec §4) | 3 |
| `tests/action/test_action_yml.py` | contract tests: manifest ↔ module ↔ README ↔ workflows | 3, 4 |
| `README.md` | "Use as a GitHub Action" section after "Drift detection" | 3 |
| `.github/workflows/action-selftest.yml` | end-to-end proof on `ubuntu-latest` against the stdio fixture image | 4 |
| `.github/workflows/release.yml` | moves the floating `v1` tag on `release: published` | 4 |
| `docs/superpowers/specs/2026-09-15-drift-detection-design.md` | §10 pointer to the new spec | 5 |
| `docs/open-decisions.md` | D3/D8 entry; retire the stale "gh auth login has not been run" paragraph | 5 |

---

### Task 1: `action.py` pure core — inputs, argv, reproduction line

**Files:**
- Create: `agent_perimeter/action.py`
- Create: `tests/action/__init__.py` (empty)
- Create: `tests/action/test_action.py`

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) class Inputs` with fields `target: str`, `mode: str`, `scope_file: str`, `image: str`, `env: tuple[str, ...]`, `only: str`, `baseline: str`, `snapshot: str`, `fail_on_drift: bool`, `sarif: str`, `html: str`, `upload_sarif: bool`
  - `class InputError(ValueError)` — message is the user-facing text; `main` prints it and exits 2
  - `def read_inputs(environ: Mapping[str, str]) -> Inputs`
  - `def build_argv(inputs: Inputs, *, first_run: bool) -> list[str]`
  - `def reproduction_line(argv: Sequence[str]) -> str`
  - `DRIFT_CHECK_ID = "drift.description_drift"` (module constant, mirrors `agent_perimeter/checks/drift/description_drift.py:37` — importing the check package would drag the whole checks tree into a glue module; a test in Task 2 asserts the two strings are equal)
  - `INPUT_NAMES: tuple[str, ...]` — the twelve kebab-case input names, used by Task 3's contract test

- [ ] **Step 1: Create the branch and the test package**

```bash
git switch -c github-action
mkdir -p tests/action && : > tests/action/__init__.py
```

- [ ] **Step 2: Write the failing tests for `read_inputs`**

`tests/action/test_action.py`:

```python
"""Unit tests for the GitHub Action entry point (spec §5–§7).

`subprocess.run` is never called for real here: Task 2 injects a fake
`run` callable. These tests cover the pure functions only.
"""

from __future__ import annotations

import shlex

import pytest

from agent_perimeter.action import (
    INPUT_NAMES,
    InputError,
    Inputs,
    build_argv,
    read_inputs,
    reproduction_line,
)


def _env(**overrides: str) -> dict[str, str]:
    """A GitHub-shaped environment: INPUT_<UPPER-KEBAB> keys, all present."""
    base = {f"INPUT_{name.upper()}": "" for name in INPUT_NAMES}
    base.update(
        {
            "INPUT_TARGET": "https://mcp.example.test/rpc",
            "INPUT_MODE": "passive",
            "INPUT_BASELINE": ".agent-perimeter/baseline.json",
            "INPUT_SNAPSHOT": ".agent-perimeter/current.json",
            "INPUT_FAIL-ON-DRIFT": "true",
            "INPUT_SARIF": "agent-perimeter.sarif",
            "INPUT_UPLOAD-SARIF": "true",
        }
    )
    for key, value in overrides.items():
        base[f"INPUT_{key.upper().replace('_', '-')}"] = value
    return base


def test_input_names_are_the_twelve_kebab_case_inputs_from_the_spec() -> None:
    assert INPUT_NAMES == (
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


def test_read_inputs_maps_every_input_and_parses_booleans() -> None:
    inputs = read_inputs(_env(env="A=1\n\nB=two\n", fail_on_drift="false", only="x.y"))
    assert inputs == Inputs(
        target="https://mcp.example.test/rpc",
        mode="passive",
        scope_file="",
        image="",
        env=("A=1", "B=two"),
        only="x.y",
        baseline=".agent-perimeter/baseline.json",
        snapshot=".agent-perimeter/current.json",
        fail_on_drift=False,
        sarif="agent-perimeter.sarif",
        html="",
        upload_sarif=True,
    )


def test_read_inputs_strips_whitespace_around_env_lines() -> None:
    assert read_inputs(_env(env="  A=1  \r\n B=2 ")).env == ("A=1", "B=2")


def test_read_inputs_rejects_target_and_image_both_empty() -> None:
    with pytest.raises(InputError) as exc:
        read_inputs(_env(target=""))
    assert "Set the `target` input" in str(exc.value)
    assert "`image`" in str(exc.value)


def test_read_inputs_allows_empty_target_when_image_is_set() -> None:
    inputs = read_inputs(_env(target="", image="ghcr.io/example/server:1"))
    assert inputs.target == "" and inputs.image == "ghcr.io/example/server:1"


@pytest.mark.parametrize("name", ["fail-on-drift", "upload-sarif"])
def test_read_inputs_rejects_non_boolean_flags(name: str) -> None:
    with pytest.raises(InputError) as exc:
        read_inputs(_env(**{name.replace("-", "_"): "yes"}))
    assert f"`{name}`" in str(exc.value)
    assert "true" in str(exc.value) and "false" in str(exc.value)


def test_read_inputs_missing_key_is_treated_as_empty() -> None:
    env = _env()
    del env["INPUT_HTML"]
    assert read_inputs(env).html == ""
```

- [ ] **Step 3: Run them — expect ImportError**

Run: `.venv/Scripts/pytest tests/action/test_action.py -q --no-cov`
Expected: FAIL at collection with `ModuleNotFoundError: No module named 'agent_perimeter.action'`.

- [ ] **Step 4: Implement `Inputs`, `read_inputs`, `INPUT_NAMES`, `InputError`**

`agent_perimeter/action.py`:

```python
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
    env_lines = tuple(
        line.strip() for line in _get(environ, "env").splitlines() if line.strip()
    )
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
```

Leave `build_argv` and `reproduction_line` out for now — Step 6 adds their tests RED first. Because the test file imports them at module level, Step 5 will still fail at collection; that is expected.

- [ ] **Step 5: Run — still a collection error, on the two missing names**

Run: `.venv/Scripts/pytest tests/action/test_action.py -q --no-cov`
Expected: `ImportError: cannot import name 'build_argv' from 'agent_perimeter.action'`. Do not stub the two functions to get green here; proceed to Step 6.

- [ ] **Step 6: Append the failing tests for `build_argv` and `reproduction_line`**

Append to `tests/action/test_action.py`:

```python
def test_first_run_writes_the_snapshot_to_the_baseline_path_and_never_gates() -> None:
    argv = build_argv(read_inputs(_env()), first_run=True)
    assert argv == [
        "agent-perimeter",
        "scan",
        "--target",
        "https://mcp.example.test/rpc",
        "--mode",
        "passive",
        "--sarif",
        "agent-perimeter.sarif",
        "--snapshot",
        ".agent-perimeter/baseline.json",
    ]
    assert "--baseline" not in argv and "--fail-on-drift" not in argv


def test_gate_run_diffs_against_the_baseline_and_gates() -> None:
    argv = build_argv(read_inputs(_env()), first_run=False)
    assert argv[-5:] == [
        "--baseline",
        ".agent-perimeter/baseline.json",
        "--snapshot",
        ".agent-perimeter/current.json",
        "--fail-on-drift",
    ]


def test_gate_run_omits_fail_on_drift_when_disabled() -> None:
    argv = build_argv(read_inputs(_env(fail_on_drift="false")), first_run=False)
    assert "--baseline" in argv and "--fail-on-drift" not in argv


def test_optional_flags_appear_only_when_set() -> None:
    inputs = read_inputs(
        _env(
            scope_file="scope.yaml",
            mode="active",
            image="ghcr.io/example/server:1",
            only="revision.cache_scope",
            html="report.html",
            env="A=1\nB=2",
        )
    )
    argv = build_argv(inputs, first_run=True)
    assert argv[argv.index("--scope-file") + 1] == "scope.yaml"
    assert argv[argv.index("--image") + 1] == "ghcr.io/example/server:1"
    assert argv[argv.index("--only") + 1] == "revision.cache_scope"
    assert argv[argv.index("--html") + 1] == "report.html"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--env"] == ["A=1", "B=2"]
    bare = build_argv(read_inputs(_env()), first_run=True)
    for flag in ("--scope-file", "--image", "--only", "--html", "--env"):
        assert flag not in bare


def test_active_mode_without_scope_file_passes_no_scope_flag_at_all() -> None:
    """Rule 1 boundary: the action never invents a scope file. The CLI's own
    refusal is the gate, so the argv must reach it with no --scope-file."""
    argv = build_argv(read_inputs(_env(mode="active")), first_run=True)
    assert "--scope-file" not in argv
    assert argv[argv.index("--mode") + 1] == "active"


def test_empty_target_with_image_is_passed_as_an_empty_string() -> None:
    argv = build_argv(read_inputs(_env(target="", image="img:1")), first_run=True)
    assert argv[argv.index("--target") + 1] == ""


def test_reproduction_line_is_shell_quoted_argv_with_env_values_masked() -> None:
    argv = build_argv(
        read_inputs(_env(target="python /srv/server.py", env="TOKEN=s3cret\nMODE=x")),
        first_run=False,
    )
    line = reproduction_line(argv)
    assert "s3cret" not in line
    assert "--env TOKEN=*** --env MODE=***" in line
    unmasked = [a for a in argv if "=" not in a or a.startswith("--")]
    for part in unmasked:
        assert shlex.quote(part) in line
    assert line.startswith("agent-perimeter scan --target 'python /srv/server.py'")
```

- [ ] **Step 7: Run — expect ImportError on the two new names**

Run: `.venv/Scripts/pytest tests/action/test_action.py -q --no-cov`
Expected: FAIL at collection, `cannot import name 'build_argv'`.

- [ ] **Step 8: Implement `build_argv` and `reproduction_line`**

Append to `agent_perimeter/action.py`:

```python
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
    server; they must never land in a job log.
    """
    masked: list[str] = []
    previous = ""
    for part in argv:
        if previous == "--env":
            key, _, _ = part.partition("=")
            masked.append(f"{key}=***")
        else:
            masked.append(part)
        previous = part
    return shlex.join(masked)
```

(`shlex.join` renders an empty argument as `''`, which is what the empty-target case needs.)

- [ ] **Step 9: Run the whole file — all green**

Run: `.venv/Scripts/pytest tests/action/test_action.py -q --no-cov`
Expected: all PASS.

- [ ] **Step 10: The gate, then commit**

```bash
.venv/Scripts/ruff check . --exclude .claude && .venv/Scripts/ruff format . --exclude .claude && .venv/Scripts/mypy --strict agent_perimeter
git add agent_perimeter/action.py tests/action/
git commit -m "feat(action): input parsing and scan argv assembly for the GitHub Action

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `action.py` runtime — subprocess, SARIF, outputs, summary, `main`

**Files:**
- Modify: `agent_perimeter/action.py`
- Modify: `tests/action/test_action.py`

**Interfaces:**
- Consumes: everything from Task 1.
- Produces:
  - `def read_sarif(path: Path) -> dict[str, Any] | None` — `None` when absent
  - `def sarif_results(sarif: Mapping[str, Any] | None) -> list[dict[str, Any]]`
  - `def drift_verdict(sarif: Mapping[str, Any] | None, *, first_run: bool) -> str` — `"none" | "true" | "false"`
  - `def write_outputs(path: Path | None, outputs: Mapping[str, str]) -> None` — appends `key=value` lines; `None` prints to stdout with a `::notice::`
  - `def write_summary(path: Path | None, text: str) -> None` — same fallback
  - `def render_summary(inputs: Inputs, sarif: Mapping[str, Any] | None, *, first_run: bool, rc: int) -> str`
  - `def main(*, environ: Mapping[str, str] | None = None, run: Callable[[list[str]], int] | None = None) -> int` — returns the exit code; `run` defaults to a `subprocess.run(...).returncode` wrapper and is the seam tests use

- [ ] **Step 1: Write the failing tests**

Append to `tests/action/test_action.py`. Add `import json`, `from pathlib import Path`, `from typing import Any` at the top (keep imports sorted for ruff `I`), and extend the `agent_perimeter.action` import list with `DRIFT_CHECK_ID, drift_verdict, main, read_sarif, render_summary, sarif_results`:

```python
def _sarif(*results: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "agent-perimeter"}},
                "properties": {"revision_claimed": "2026-07-28", "target": "t"},
                "results": list(results),
            }
        ],
    }


def _result(rule: str, level: str = "warning") -> dict[str, Any]:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": "attacker-authored text that must not reach the summary"},
    }


class FakeRun:
    """Stands in for subprocess.run: records argv, writes a SARIF (or not),
    returns a chosen exit code."""

    def __init__(self, rc: int, sarif: dict[str, Any] | None) -> None:
        self.rc = rc
        self.sarif = sarif
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> int:
        self.calls.append(list(argv))
        if self.sarif is not None:
            Path(argv[argv.index("--sarif") + 1]).write_text(json.dumps(self.sarif))
        return self.rc


def _gh(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = _env(
        baseline=str(tmp_path / ".agent-perimeter" / "baseline.json"),
        snapshot=str(tmp_path / ".agent-perimeter" / "current.json"),
        sarif=str(tmp_path / "out" / "r.sarif"),
        **overrides,
    )
    env["GITHUB_OUTPUT"] = str(tmp_path / "gh_output")
    env["GITHUB_STEP_SUMMARY"] = str(tmp_path / "gh_summary")
    return env


def _outputs(tmp_path: Path) -> dict[str, str]:
    lines = (tmp_path / "gh_output").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines)


def _existing_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / ".agent-perimeter" / "baseline.json"
    baseline.parent.mkdir()
    baseline.write_text("{}")


def test_drift_check_id_matches_the_registered_check() -> None:
    from agent_perimeter.checks.drift.description_drift import CHECK

    assert DRIFT_CHECK_ID == CHECK.id


def test_read_sarif_returns_none_when_absent(tmp_path: Path) -> None:
    assert read_sarif(tmp_path / "missing.sarif") is None


def test_sarif_results_handles_none_and_missing_runs() -> None:
    assert sarif_results(None) == []
    assert sarif_results({"runs": []}) == []
    assert len(sarif_results(_sarif(_result("a"), _result("b")))) == 2


def test_drift_verdict() -> None:
    assert drift_verdict(_sarif(), first_run=True) == "none"
    assert drift_verdict(_sarif(_result(DRIFT_CHECK_ID)), first_run=True) == "none"
    assert drift_verdict(_sarif(_result("x")), first_run=False) == "false"
    assert drift_verdict(_sarif(_result(DRIFT_CHECK_ID)), first_run=False) == "true"
    assert drift_verdict(None, first_run=False) == "false"


def test_first_run_creates_parent_dirs_writes_baseline_and_reports(tmp_path: Path) -> None:
    run = FakeRun(0, _sarif(_result("revision.cache_scope")))
    rc = main(environ=_gh(tmp_path), run=run)
    assert rc == 0
    argv = run.calls[0]
    assert argv[argv.index("--snapshot") + 1].endswith("baseline.json")
    assert (tmp_path / ".agent-perimeter").is_dir() and (tmp_path / "out").is_dir()
    out = _outputs(tmp_path)
    assert out["baseline-created"] == "true"
    assert out["drift"] == "none"
    assert out["finding-count"] == "1"
    assert out["snapshot-file"].endswith("baseline.json")
    assert out["sarif-file"].endswith("r.sarif")
    summary = (tmp_path / "gh_summary").read_text()
    assert "Commit it to arm the drift gate" in summary


def test_gate_run_with_drift_exits_3_and_reports_true(tmp_path: Path) -> None:
    _existing_baseline(tmp_path)
    run = FakeRun(3, _sarif(_result(DRIFT_CHECK_ID, "error"), _result("x")))
    rc = main(environ=_gh(tmp_path), run=run)
    assert rc == 3
    assert "--fail-on-drift" in run.calls[0]
    out = _outputs(tmp_path)
    assert out["baseline-created"] == "false"
    assert out["drift"] == "true"
    assert out["finding-count"] == "2"
    assert out["snapshot-file"].endswith("current.json")
    summary = (tmp_path / "gh_summary").read_text()
    assert "Drift gate tripped" in summary
    assert "agent-perimeter drift" in summary
    assert "attacker-authored" not in summary  # rule 5


def test_gate_run_clean_exits_0_and_reports_false(tmp_path: Path) -> None:
    _existing_baseline(tmp_path)
    rc = main(environ=_gh(tmp_path), run=FakeRun(0, _sarif()))
    assert rc == 0
    out = _outputs(tmp_path)
    assert out["drift"] == "false" and out["finding-count"] == "0"


def test_soft_gate_reports_drift_but_exits_0(tmp_path: Path) -> None:
    _existing_baseline(tmp_path)
    run = FakeRun(0, _sarif(_result(DRIFT_CHECK_ID)))
    rc = main(environ=_gh(tmp_path, fail_on_drift="false"), run=run)
    assert rc == 0
    assert "--fail-on-drift" not in run.calls[0]
    assert _outputs(tmp_path)["drift"] == "true"


def test_rc_zero_without_sarif_is_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(environ=_gh(tmp_path), run=FakeRun(0, None))
    assert rc == 2
    assert "wrote no SARIF" in capsys.readouterr().out
    assert "sarif-file" not in _outputs(tmp_path)


def test_nonzero_rc_without_sarif_still_writes_outputs(tmp_path: Path) -> None:
    rc = main(environ=_gh(tmp_path), run=FakeRun(2, None))
    assert rc == 2
    out = _outputs(tmp_path)
    assert out["finding-count"] == "0" and out["drift"] == "none"
    assert "sarif-file" not in out


def test_input_error_exits_2_and_runs_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = FakeRun(0, _sarif())
    rc = main(environ=_gh(tmp_path, target="", image=""), run=run)
    assert rc == 2 and run.calls == []
    assert "Set the `target` input" in capsys.readouterr().out


def test_reproduction_line_is_printed_before_the_run_and_matches_argv(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = FakeRun(0, _sarif())
    main(environ=_gh(tmp_path, env="TOKEN=s3cret"), run=run)
    out = capsys.readouterr().out
    first = out.splitlines()[0]
    assert first.startswith("Reproduction: agent-perimeter scan")
    assert "s3cret" not in out
    assert first == "Reproduction: " + reproduction_line(run.calls[0])


def test_active_mode_never_creates_a_scope_file(tmp_path: Path) -> None:
    before = set(tmp_path.rglob("*"))
    main(environ=_gh(tmp_path, mode="active"), run=FakeRun(2, None))
    created = set(tmp_path.rglob("*")) - before
    assert all(p.name in {"gh_output", "gh_summary"} or p.is_dir() for p in created)


def test_outputs_fall_back_to_stdout_when_github_vars_are_unset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = _gh(tmp_path)
    del env["GITHUB_OUTPUT"], env["GITHUB_STEP_SUMMARY"]
    main(environ=env, run=FakeRun(0, _sarif()))
    out = capsys.readouterr().out
    assert "::notice::GITHUB_OUTPUT is not set" in out
    assert "baseline-created=true" in out
    assert "::notice::GITHUB_STEP_SUMMARY is not set" in out


def test_render_summary_counts_by_severity_and_shows_revision() -> None:
    inputs = read_inputs(_env())
    sarif = _sarif(_result("a", "error"), _result("b", "warning"), _result("c", "warning"))
    text = render_summary(inputs, sarif, first_run=False, rc=0)
    assert "| Revision claimed | 2026-07-28 |" in text
    assert "| error | 1 |" in text and "| warning | 2 |" in text
    assert "| Drift | false |" in text
    assert "attacker-authored" not in text
```

- [ ] **Step 2: Run — expect ImportError on the new names**

Run: `.venv/Scripts/pytest tests/action/test_action.py -q --no-cov`
Expected: FAIL at collection, `cannot import name 'drift_verdict'`.

- [ ] **Step 3: Implement the runtime half**

Append to `agent_perimeter/action.py`, and extend the imports to:

```python
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
```

then:

```python
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
```

Cross-check against the tests before running: `test_nonzero_rc_without_sarif_still_writes_outputs` expects `drift == "none"` — no baseline exists there, so `first_run` is true; correct. `test_first_run_…` asserts `out/` is created for the SARIF — the `mkdir` loop does that. `S603` is globally ignored in `pyproject.toml`, so `subprocess.run` needs no `noqa`.

- [ ] **Step 4: Run — all green**

Run: `.venv/Scripts/pytest tests/action/ -q --no-cov`
Expected: all PASS.

- [ ] **Step 5: Run the module for real once, locally, to see the stdout fallback path**

```bash
env INPUT_TARGET=https://127.0.0.1:9/nothing INPUT_MODE=passive INPUT_BASELINE=/tmp/ap-b.json INPUT_SNAPSHOT=/tmp/ap-c.json INPUT_FAIL-ON-DRIFT=true INPUT_SARIF=/tmp/ap.sarif INPUT_UPLOAD-SARIF=true PATH=".venv/Scripts:$PATH" .venv/Scripts/python -m agent_perimeter.action; echo "exit=$?"
rm -f /tmp/ap-b.json /tmp/ap-c.json /tmp/ap.sarif
```

Expected: first line `Reproduction: agent-perimeter scan --target https://127.0.0.1:9/nothing …`, then the CLI's own connection-failure output, then `::notice::GITHUB_OUTPUT is not set…` with `baseline-created=true`, `drift=none`, `finding-count=0`, and a non-zero exit. (`env` is used because `INPUT_FAIL-ON-DRIFT=…` is not a valid shell assignment.)

- [ ] **Step 6: Coverage check for the module, the gate, commit**

Run: `.venv/Scripts/pytest tests/action/ -q --cov=agent_perimeter.action --cov-report=term-missing --cov-fail-under=0`
Expected: `agent_perimeter/action.py` at 100% (the two `pragma: no cover` spots are the only executable lines not hit).

```bash
.venv/Scripts/ruff check . --exclude .claude && .venv/Scripts/ruff format . --exclude .claude && .venv/Scripts/mypy --strict agent_perimeter
git add agent_perimeter/action.py tests/action/test_action.py
git commit -m "feat(action): run the scan, derive outputs and job summary from the SARIF

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `action.yml`, README section, contract test

**Files:**
- Create: `action.yml`
- Create: `tests/action/test_action_yml.py`
- Modify: `README.md` (insert a new section between "### Drift detection" and "## CI: SARIF in GitHub code scanning", currently line 108)

**Interfaces:**
- Consumes: `INPUT_NAMES` from `agent_perimeter.action`; the five output names written by `main` (`sarif-file`, `snapshot-file`, `baseline-created`, `drift`, `finding-count`).
- Produces: `action.yml` inputs/outputs exactly as spec §4; a README section titled `## Use as a GitHub Action`.

- [ ] **Step 1: Write the failing contract tests**

`tests/action/test_action_yml.py`:

```python
"""action.yml <-> action.py <-> README <-> workflows stay in agreement."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from agent_perimeter.action import INPUT_NAMES

MANIFEST = Path("action.yml")
README = Path("README.md")
OUTPUT_NAMES = ("sarif-file", "snapshot-file", "baseline-created", "drift", "finding-count")
PINNED = re.compile(r"@(v\d+\.\d+\.\d+|[0-9a-f]{40})$")
UPLOAD_IF = "always() && inputs.upload-sarif == 'true' && steps.scan.outputs.sarif-file != ''"


def _manifest() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    return loaded


def test_manifest_declares_exactly_the_module_inputs_with_descriptions() -> None:
    inputs = _manifest()["inputs"]
    assert tuple(inputs) == INPUT_NAMES
    for name, spec in inputs.items():
        assert spec.get("description", "").strip(), f"{name} has no description"


def test_manifest_defaults_match_the_spec() -> None:
    inputs = _manifest()["inputs"]
    assert inputs["mode"]["default"] == "passive"
    assert inputs["baseline"]["default"] == ".agent-perimeter/baseline.json"
    assert inputs["snapshot"]["default"] == ".agent-perimeter/current.json"
    assert inputs["fail-on-drift"]["default"] == "true"
    assert inputs["sarif"]["default"] == "agent-perimeter.sarif"
    assert inputs["upload-sarif"]["default"] == "true"
    # target may legitimately be empty when image is set; the module enforces the rule
    assert inputs["target"].get("required") is not True


def test_manifest_declares_exactly_the_module_outputs() -> None:
    outputs = _manifest()["outputs"]
    assert tuple(outputs) == OUTPUT_NAMES
    for name, spec in outputs.items():
        assert spec["value"] == f"${{{{ steps.scan.outputs.{name} }}}}", name


def test_manifest_is_composite_with_the_pinned_steps_and_branding() -> None:
    m = _manifest()
    assert m["runs"]["using"] == "composite"
    assert m["branding"] == {"icon": "shield", "color": "yellow"}
    steps = m["runs"]["steps"]
    uses = [s["uses"] for s in steps if "uses" in s]
    assert uses[0].startswith("astral-sh/setup-uv@")
    assert uses[-1].startswith("github/codeql-action/upload-sarif@")
    for ref in uses:
        assert PINNED.search(ref), f"{ref} is not pinned to a full version or SHA"
    scan = next(s for s in steps if s.get("id") == "scan")
    assert scan["run"].strip() == "python -m agent_perimeter.action"
    assert scan["shell"] == "bash"
    for name in INPUT_NAMES:
        assert scan["env"][f"INPUT_{name.upper()}"] == f"${{{{ inputs.{name} }}}}"
    upload = steps[-1]
    assert upload["if"] == UPLOAD_IF
    assert upload["with"]["sarif_file"] == "${{ steps.scan.outputs.sarif-file }}"


def test_install_step_installs_from_the_action_path() -> None:
    steps = _manifest()["runs"]["steps"]
    install = next(s for s in steps if "run" in s and "pip install" in s["run"])
    assert '"${{ github.action_path }}"' in install["run"]
    assert "--system" in install["run"]


def test_readme_documents_every_input_and_the_permission() -> None:
    body = README.read_text(encoding="utf-8")
    start = body.index("## Use as a GitHub Action")
    end = body.index("## CI: SARIF in GitHub code scanning")
    section = body[start:end]
    for name in INPUT_NAMES:
        assert f"`{name}`" in section, f"README section does not mention `{name}`"
    assert "security-events: write" in section
    assert "uses: Berakhah/agent-perimeter@v1" in section
    assert "`3`" in section
```

- [ ] **Step 2: Run — expect FileNotFoundError on `action.yml`**

Run: `.venv/Scripts/pytest tests/action/test_action_yml.py -q --no-cov`
Expected: every test FAILS (`FileNotFoundError: action.yml`; the README test with `ValueError: substring not found`).

- [ ] **Step 3: Write `action.yml`**

```yaml
name: Agent Perimeter
description: >-
  Scan an MCP server, upload SARIF to code scanning, and fail the job when
  its tools drift from a committed baseline.
author: Berakhah
branding:
  icon: shield
  color: yellow

inputs:
  target:
    description: >-
      A URL (Streamable HTTP) or a stdio command to launch. May be empty when
      `image` is set, in which case the image's own entrypoint is the server.
    default: ""
  mode:
    description: "`passive` or `active`. Active mode refuses to run without `scope-file`."
    default: passive
  scope-file:
    description: >-
      Path to the scope file authorising active mode. The action never creates
      one; the CLI exits 2 without it.
    default: ""
  image:
    description: Container image for stdio targets (default is the CLI's `python:3.12-slim`).
    default: ""
  env:
    description: Environment for a stdio target, one `KEY=VALUE` per line. Values are never logged.
    default: ""
  only:
    description: Run a single check by id.
    default: ""
  baseline:
    description: >-
      Committed tool snapshot to diff against. When the file does not exist
      the action writes this scan's snapshot there and exits 0; commit it.
    default: .agent-perimeter/baseline.json
  snapshot:
    description: Where this scan's snapshot is written on a gate run.
    default: .agent-perimeter/current.json
  fail-on-drift:
    description: "`true` to exit 3 when any tool changed since `baseline`."
    default: "true"
  sarif:
    description: Where to write SARIF 2.1.0.
    default: agent-perimeter.sarif
  html:
    description: Where to write the HTML report (omitted when empty).
    default: ""
  upload-sarif:
    description: "`true` to upload the SARIF to code scanning (needs `security-events: write`)."
    default: "true"

outputs:
  sarif-file:
    description: Path of the SARIF written (absent when the scan wrote none).
    value: ${{ steps.scan.outputs.sarif-file }}
  snapshot-file:
    description: Path the tool snapshot was written to (`baseline` on a first run).
    value: ${{ steps.scan.outputs.snapshot-file }}
  baseline-created:
    description: "`true` when this run wrote the baseline because none existed."
    value: ${{ steps.scan.outputs.baseline-created }}
  drift:
    description: "`none` on a first run; else `true`/`false` from the SARIF, independent of `fail-on-drift`."
    value: ${{ steps.scan.outputs.drift }}
  finding-count:
    description: Number of SARIF results.
    value: ${{ steps.scan.outputs.finding-count }}

runs:
  using: composite
  steps:
    - uses: astral-sh/setup-uv@v10.1.0
      with:
        python-version: "3.12"
    - name: Install agent-perimeter from this action's checkout
      shell: bash
      run: uv pip install --system "${{ github.action_path }}"
    - id: scan
      name: Scan
      shell: bash
      env:
        INPUT_TARGET: ${{ inputs.target }}
        INPUT_MODE: ${{ inputs.mode }}
        INPUT_SCOPE-FILE: ${{ inputs.scope-file }}
        INPUT_IMAGE: ${{ inputs.image }}
        INPUT_ENV: ${{ inputs.env }}
        INPUT_ONLY: ${{ inputs.only }}
        INPUT_BASELINE: ${{ inputs.baseline }}
        INPUT_SNAPSHOT: ${{ inputs.snapshot }}
        INPUT_FAIL-ON-DRIFT: ${{ inputs.fail-on-drift }}
        INPUT_SARIF: ${{ inputs.sarif }}
        INPUT_HTML: ${{ inputs.html }}
        INPUT_UPLOAD-SARIF: ${{ inputs.upload-sarif }}
      run: python -m agent_perimeter.action
    - name: Upload SARIF to code scanning
      if: always() && inputs.upload-sarif == 'true' && steps.scan.outputs.sarif-file != ''
      uses: github/codeql-action/upload-sarif@v4.38.0
      with:
        sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

Two details worth knowing: (a) GitHub composite actions do **not** auto-populate `INPUT_*`, hence the explicit `env:` block; (b) `setup-uv` with `python-version` puts that interpreter first on PATH, and `uv pip install --system` installs into it, so `python -m …` and the `agent-perimeter` console script both resolve. `target` is declared with `default: ""` rather than `required: true` because an empty target is valid with `image`; the module enforces the real rule.

- [ ] **Step 4: Write the README section**

Insert before `## CI: SARIF in GitHub code scanning`:

````markdown
## Use as a GitHub Action

The drift recipe above as one step. On the first run there is no baseline,
so the action writes one and exits 0 — commit it. Every run after that
diffs against the committed file and exits `3` if any tool's description,
schema or annotations changed, or a tool appeared or vanished. Approving a
change is a commit that replaces the baseline, reviewed like any other.

```yaml
name: mcp-perimeter
on:
  push: { branches: [main] }
  schedule: [{ cron: "17 6 * * *" }]
permissions:
  contents: read
  security-events: write   # for the SARIF upload; set upload-sarif: "false" to skip it
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: Berakhah/agent-perimeter@v1
        with:
          target: https://mcp.example.test/rpc
```

| Input | Default | Meaning |
|---|---|---|
| `target` | — | URL or stdio command. May be empty when `image` is set (the image's entrypoint is the server). |
| `mode` | `passive` | `active` needs `scope-file`; the action never creates one. |
| `scope-file` | — | Authorisation for active mode (see "Before you scan anything"). |
| `image` | CLI default | Container image for stdio targets. |
| `env` | — | `KEY=VALUE` per line for a stdio target. Never logged. |
| `only` | — | Run one check by id. |
| `baseline` | `.agent-perimeter/baseline.json` | Committed snapshot to diff against; written on the first run. |
| `snapshot` | `.agent-perimeter/current.json` | Where a gate run writes this scan's snapshot. |
| `fail-on-drift` | `true` | `false` keeps the job green and exposes the `drift` output instead. |
| `sarif` | `agent-perimeter.sarif` | SARIF 2.1.0 output path. |
| `html` | — | HTML report path, if wanted. |
| `upload-sarif` | `true` | Upload to code scanning. |

Outputs: `sarif-file`, `snapshot-file`, `baseline-created`, `drift`
(`none` / `true` / `false`, read from the SARIF so it works with
`fail-on-drift: "false"`), `finding-count`. Exit codes are the CLI's: `0`
clean, `2` refused or usage error, `3` drift gate tripped. The step log's
first line is the exact `agent-perimeter scan …` command that ran, with
`env` values masked — paste it to reproduce.

Soft gate — annotate instead of fail:

```yaml
      - id: ap
        uses: Berakhah/agent-perimeter@v1
        with: { target: https://mcp.example.test/rpc, fail-on-drift: "false" }
      - if: steps.ap.outputs.drift == 'true'
        run: echo "::warning::MCP tools drifted; review ${{ steps.ap.outputs.snapshot-file }}"
```

The action installs the scanner from its own checkout (`@v1` tracks the
latest `v1.x.y` release); nothing is published to PyPI or a registry.
stdio targets run in the same locked-down container the CLI uses, on the
runner's Docker daemon — use an `ubuntu-*` runner.

````

- [ ] **Step 5: Run the contract tests and the docs tests — green**

Run: `.venv/Scripts/pytest tests/action/ tests/docs/ -q --no-cov`
Expected: all PASS.

- [ ] **Step 6: Sanity-count the manifest**

```bash
.venv/Scripts/python -c "import yaml; m=yaml.safe_load(open('action.yml')); print(len(m['inputs']),'inputs',len(m['outputs']),'outputs',len(m['runs']['steps']),'steps')"
```

Expected: `12 inputs 5 outputs 4 steps`.

- [ ] **Step 7: The gate, then commit**

```bash
.venv/Scripts/ruff check . --exclude .claude && .venv/Scripts/ruff format . --exclude .claude && .venv/Scripts/mypy --strict agent_perimeter
git add action.yml tests/action/test_action_yml.py README.md
git commit -m "feat(action): composite action.yml, README usage, manifest contract tests

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Self-test and release workflows

**Files:**
- Create: `.github/workflows/action-selftest.yml`
- Create: `.github/workflows/release.yml`
- Modify: `tests/action/test_action_yml.py` (append workflow tests)

**Interfaces:**
- Consumes: `action.yml` from Task 3; the fixture image at `tests/fixtures/servers` (`AP_FIXTURE_FLAW` env selects the flaw; `drift_description` changes `read_file`'s description — see `tests/fixtures/servers/server.py`).
- Produces: two workflows; the self-test is the only end-to-end proof of the action.

- [ ] **Step 1: Write the failing workflow tests**

Append to `tests/action/test_action_yml.py`:

```python
SELFTEST = Path(".github/workflows/action-selftest.yml")
RELEASE = Path(".github/workflows/release.yml")


def _workflow(path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded


def test_selftest_workflow_exercises_first_run_clean_rerun_and_drift() -> None:
    wf = _workflow(SELFTEST)
    # PyYAML parses the bare `on:` key as boolean True.
    assert set(wf[True]) == {"push", "pull_request"}
    assert wf["permissions"]["security-events"] == "write"
    job = wf["jobs"]["selftest"]
    assert job["runs-on"] == "ubuntu-latest"
    local_uses = [s for s in job["steps"] if s.get("uses") == "./"]
    assert [s["id"] for s in local_uses] == ["first", "clean", "drifted"]
    assert all(s["with"]["image"] == "agent-perimeter-fixture:selftest" for s in local_uses)
    assert local_uses[0]["with"]["env"].strip() == "AP_FIXTURE_FLAW=none"
    assert local_uses[2]["with"]["env"].strip() == "AP_FIXTURE_FLAW=drift_description"
    assert local_uses[2]["continue-on-error"] is True
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "steps.first.outputs.baseline-created" in runs
    assert "steps.clean.outputs.drift" in runs
    assert "steps.drifted.outcome" in runs and "steps.drifted.outputs.drift" in runs
    assert "drift.description_drift" in runs


def test_release_workflow_moves_the_v1_tag_on_v1_releases_only() -> None:
    wf = _workflow(RELEASE)
    assert wf[True] == {"release": {"types": ["published"]}}
    assert wf["permissions"]["contents"] == "write"
    job = wf["jobs"]["move-major-tag"]
    assert "startsWith(github.event.release.tag_name, 'v1.')" in job["if"]
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "git tag -f v1" in runs and "git push -f origin v1" in runs
```

- [ ] **Step 2: Run — expect FileNotFoundError**

Run: `.venv/Scripts/pytest tests/action/test_action_yml.py -q --no-cov -k workflow`
Expected: both FAIL with `FileNotFoundError`.

- [ ] **Step 3: Write the self-test workflow**

`.github/workflows/action-selftest.yml`:

```yaml
name: action-selftest
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  selftest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: Build the stdio fixture image
        run: docker build -t agent-perimeter-fixture:selftest tests/fixtures/servers

      # (1) No baseline exists: the action must write one and exit 0.
      - id: first
        uses: ./
        with:
          target: ""
          image: agent-perimeter-fixture:selftest
          env: |
            AP_FIXTURE_FLAW=none
          baseline: selftest/baseline.json
          snapshot: selftest/current.json
          sarif: selftest/first.sarif

      - name: Assert first run created the baseline
        run: |
          test "${{ steps.first.outputs.baseline-created }}" = "true"
          test "${{ steps.first.outputs.drift }}" = "none"
          test -s selftest/baseline.json

      # (2) Same fixture again: gate run, no drift, exit 0.
      - id: clean
        uses: ./
        with:
          target: ""
          image: agent-perimeter-fixture:selftest
          env: |
            AP_FIXTURE_FLAW=none
          baseline: selftest/baseline.json
          snapshot: selftest/current.json
          sarif: selftest/clean.sarif

      - name: Assert clean rerun reports no drift
        run: |
          test "${{ steps.clean.outputs.baseline-created }}" = "false"
          test "${{ steps.clean.outputs.drift }}" = "false"

      # (3) Description changed: gate must trip (exit 3) and still upload SARIF.
      - id: drifted
        uses: ./
        continue-on-error: true
        with:
          target: ""
          image: agent-perimeter-fixture:selftest
          env: |
            AP_FIXTURE_FLAW=drift_description
          baseline: selftest/baseline.json
          snapshot: selftest/current.json
          sarif: selftest/drifted.sarif

      - name: Assert the drift gate tripped and the SARIF names the drift check
        run: |
          test "${{ steps.drifted.outcome }}" = "failure"
          test "${{ steps.drifted.outputs.drift }}" = "true"
          python3 - <<'EOF'
          import json
          results = json.load(open("selftest/drifted.sarif"))["runs"][0]["results"]
          assert any(r["ruleId"] == "drift.description_drift" for r in results), results
          EOF

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: action-selftest
          path: selftest/
```

`continue-on-error: true` on step (3): the composite exits 3, the step's `outcome` is `failure`, the job continues, and the composite's own `always()` upload step already ran inside it.

- [ ] **Step 4: Write the release workflow**

`.github/workflows/release.yml`:

```yaml
name: release
on:
  release:
    types: [published]

permissions:
  contents: write

jobs:
  move-major-tag:
    # `uses: Berakhah/agent-perimeter@v1` must follow the newest v1.x.y.
    if: startsWith(github.event.release.tag_name, 'v1.')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - name: Point v1 at this release
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git tag -f v1 "${{ github.event.release.tag_name }}"
          git push -f origin v1
```

- [ ] **Step 5: Run the workflow tests — green**

Run: `.venv/Scripts/pytest tests/action/ -q --no-cov`
Expected: all PASS.

- [ ] **Step 6: Prove the self-test's three scenarios locally with the real CLI (Docker required)**

Same sequence the workflow runs; a failure here is cheaper to see than on CI:

```bash
docker build -t agent-perimeter-fixture:selftest tests/fixtures/servers
rm -rf /tmp/ap-selftest && mkdir -p /tmp/ap-selftest
run() { env INPUT_TARGET="" INPUT_IMAGE=agent-perimeter-fixture:selftest INPUT_ENV="AP_FIXTURE_FLAW=$1" INPUT_MODE=passive INPUT_BASELINE=/tmp/ap-selftest/baseline.json INPUT_SNAPSHOT=/tmp/ap-selftest/current.json INPUT_FAIL-ON-DRIFT=true INPUT_SARIF=/tmp/ap-selftest/$1-$2.sarif INPUT_UPLOAD-SARIF=true GITHUB_OUTPUT=/tmp/ap-selftest/out-$2 PATH=".venv/Scripts:$PATH" .venv/Scripts/python -m agent_perimeter.action; echo "exit=$?"; cat /tmp/ap-selftest/out-$2; }
run none 1; run none 2; run drift_description 3
```

Expected: exits `0`, `0`, `3`; outputs show `baseline-created=true`, `false`, `false` and `drift=none`, `false`, `true`.

- [ ] **Step 7: The gate, then commit**

```bash
.venv/Scripts/ruff check . --exclude .claude && .venv/Scripts/ruff format . --exclude .claude && .venv/Scripts/mypy --strict agent_perimeter
git add .github/workflows/action-selftest.yml .github/workflows/release.yml tests/action/test_action_yml.py
git commit -m "ci: action self-test against the stdio fixture; release workflow moves the v1 tag

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Docs, full suite, push, watch CI (STOP before merging and tagging)

**Files:**
- Modify: `docs/superpowers/specs/2026-09-15-drift-detection-design.md:319`
- Modify: `docs/open-decisions.md` (replace the stale trailing paragraph; append an addendum)
- Modify: `docs/superpowers/specs/2026-09-16-github-action-design.md:4` (status line)

- [ ] **Step 1: Point the drift spec at the new one**

Replace line 319 of the drift spec (`- A GitHub Action wrapper (\`agent-perimeter/scan@v1\`). Natural follow-on; needs the marketplace/publishing decision first.`) with:

```markdown
- A GitHub Action wrapper (`agent-perimeter/scan@v1`). Built 2026-09-16 — see `2026-09-16-github-action-design.md`; the publishing decision it needed is that spec's D3/D8.
```

- [ ] **Step 2: Record the decision in `docs/open-decisions.md`**

Replace the stale final paragraph (the one beginning `Local \`main\` was 64 commits ahead of \`origin/main\` as of 2026-09-14` and ending `a local edit).`) with:

```markdown
*Addendum, 2026-09-16.* The sync above happened on 2026-09-14/15 (`gh auth
login` done, `origin/main` current, `.github/workflows/ci.yml` green on
every push since). "CI is green" is now usable evidence.

## Addendum — GitHub Action delivery (2026-09-16)

The drift spec (`docs/superpowers/specs/2026-09-15-drift-detection-design.md`
§10) deferred a GitHub Action pending a publishing decision. Decided, with
the reasoning in `2026-09-16-github-action-design.md` D3/D8:

- **Delivery: install from this repo at the action's own ref.** `action.yml`
  at the root; `uses: Berakhah/agent-perimeter@v1` installs `agent_perimeter`
  from the action's checkout. No PyPI release, no GHCR image — both would add
  a recurring publishing surface for a package that has never been released,
  and neither is needed for the action to work.
- **Marketplace: not listed.** `branding` is in place so a listing is one
  click; listing implies support expectations that are a human-partner call.
- **Versioning:** `v1.0.0` release + floating `v1` tag moved by
  `.github/workflows/release.yml`.
```

- [ ] **Step 3: Update the new spec's status line**

Line 4 of `docs/superpowers/specs/2026-09-16-github-action-design.md` becomes:

```markdown
**Status:** implemented 2026-09-16 (plan: `docs/superpowers/plans/2026-09-16-github-action.md`)
```

- [ ] **Step 4: Full suite, gate, coverage**

Run: `.venv/Scripts/pytest -q`
Expected: all PASS, coverage ≥ 75% (`--cov-fail-under=75` in `pyproject.toml` enforces it). Then the gate.

- [ ] **Step 5: Review the diff for names and secrets, commit**

```bash
git status
git grep -nE "gho_|ghp_|AKIA|-----BEGIN" -- action.yml .github tests/action agent_perimeter/action.py || echo "no secrets"
git add docs/superpowers/specs/2026-09-15-drift-detection-design.md docs/open-decisions.md docs/superpowers/specs/2026-09-16-github-action-design.md
git commit -m "docs: record the GitHub Action delivery decision; retire the stale sync note

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Push the branch and open a PR so `action-selftest` runs on a real runner**

```bash
git push -u origin github-action
gh pr create --title "feat: GitHub Action wrapper (drift gate + SARIF)" --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-09-16-github-action-design.md.

- `action.yml` composite: install from the action's own checkout, run `python -m agent_perimeter.action`, upload SARIF (always, so a drift failure still uploads).
- `agent_perimeter/action.py`: first-run vs gate-run, exact reproduction line with `env` values masked, outputs + job summary derived from the SARIF, exit codes unchanged (0/2/3).
- `action-selftest.yml`: first run -> clean rerun -> drifted fixture (exit 3) on ubuntu-latest, proving the containerised stdio launcher on a GitHub runner.
- `release.yml`: moves the `v1` tag on `v1.*` releases.
- README "Use as a GitHub Action"; open-decisions addendum (install-from-ref, no PyPI/GHCR, no Marketplace listing yet).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
gh pr checks --watch
```

Expected: `ci`, `web`, `action-selftest` all green. If `action-selftest` fails, read `gh run view --log-failed`. Likeliest causes: (a) `uv pip install --system` cannot find the interpreter — confirm the `python-version` line on the `setup-uv` step survived; (b) `python -m agent_perimeter.action` runs but `agent-perimeter` is not on PATH — switch the scan step's `run:` to `python -m agent_perimeter.action` *and* set `PATH="$(python -c 'import sysconfig;print(sysconfig.get_path("scripts"))'):$PATH"` on the line before it (then update the contract test's `run` assertion to `endswith`); (c) the runner's Docker refuses a launcher flag — compare with `tests/test_cli_integration.py`, which runs the same launcher in the `ci` job and passes, so this should not differ.

- [ ] **Step 7: STOP — ask the human partner before merging and tagging**

Merging to `main` and creating the `v1.0.0` release are visible, external actions. Report the three green checks and ask for go-ahead. On yes:

```bash
gh pr merge --squash --delete-branch
git switch main && git pull
gh release create v1.0.0 --title "v1.0.0 - GitHub Action" --notes "First tagged release. \`uses: Berakhah/agent-perimeter@v1\` - see README \"Use as a GitHub Action\"."
gh run list --workflow release --limit 1   # expect: the v1 tag move ran and succeeded
git fetch --tags && git tag --points-at v1  # expect: v1.0.0
```

---

## Self-review against the spec

- §2 D1–D8: D1/D7 → Task 2 outputs + Task 3 upload step; D2 → Task 4 self-test on `ubuntu-latest` with stdio; D3 → Task 3 install step + Task 5 docs; D4 → Task 1 `build_argv` first-run branch, Task 2 mkdir + summary callout; D5/D6 → Tasks 1–2; D8 → Task 4 `release.yml`, Task 5 Step 7.
- §3 hard rules: rule 1 → `test_active_mode_without_scope_file_passes_no_scope_flag_at_all` and `test_active_mode_never_creates_a_scope_file`; rule 3 → `test_reproduction_line_is_shell_quoted_argv_with_env_values_masked` and the `s3cret` assertions in Task 2; rule 5 → `attacker-authored` assertions on summary.
- §4 inputs/outputs/steps/`if:` → Task 3 manifest + contract test asserts the exact `if:` string and every `INPUT_*` mapping.
- §5 flow incl. mkdir of parents, reproduction line first, rc-0-without-SARIF → Task 2.
- §6 error table → `read_inputs` errors, `test_rc_zero_without_sarif_is_exit_2`, stdout fallback test; scope refusal and invalid baseline are deliberately passed through (covered by the argv tests).
- §7 tests → Tasks 1, 2 (unit), 3, 4 (contract, workflows), 4 (self-test), release test in Task 4.
- §8 documents → Task 3 README, Task 5 the rest.
- Type consistency: `Inputs` field names used in `build_argv`, `render_summary`, `main` match Task 1's dataclass; `FakeRun.__call__(argv: list[str]) -> int` matches `main`'s `run: Callable[[list[str]], int]`; output keys in `main` match `OUTPUT_NAMES` in Task 3 and the `outputs:` block of `action.yml`; `main` takes keyword-only `environ`/`run` everywhere it is called.
