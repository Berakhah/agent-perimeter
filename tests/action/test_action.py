"""Unit tests for the GitHub Action entry point (spec §5–§7).

`subprocess.run` is never called for real here: Task 2 injects a fake
`run` callable. These tests cover the pure functions only.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import pytest

from agent_perimeter import action as action_module
from agent_perimeter.action import (
    DRIFT_CHECK_ID,
    INPUT_NAMES,
    InputError,
    Inputs,
    _subprocess_run,
    build_argv,
    drift_verdict,
    main,
    read_inputs,
    read_sarif,
    render_summary,
    reproduction_line,
    sarif_results,
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


def test_read_inputs_rejects_malformed_env_line_without_leaking_the_value() -> None:
    """Finding 1: a bare token (no '=') must be rejected before it ever
    reaches the CLI, whose own error echo would print it unmasked."""
    with pytest.raises(InputError) as exc:
        read_inputs(_env(env="A=1\nsecret-token-no-equals\nB=2"))
    message = str(exc.value)
    assert "secret-token-no-equals" not in message
    assert "line 2" in message


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
    assert "--env 'TOKEN=***' --env 'MODE=***'" in line
    unmasked = [a for a in argv if "=" not in a or a.startswith("--")]
    for part in unmasked:
        assert shlex.quote(part) in line
    assert line.startswith("agent-perimeter scan --target 'python /srv/server.py'")


def test_reproduction_line_masks_malformed_env_token_entirely() -> None:
    """Rule 3: malformed env tokens without '=' must not appear unmasked."""
    # Simulate a malformed env value (no '=') by directly constructing argv
    argv = [
        "agent-perimeter",
        "scan",
        "--target",
        "https://example.test",
        "--env",
        "bare_token_no_equals",  # Malformed: no KEY=VALUE structure
    ]
    line = reproduction_line(argv)
    assert "bare_token_no_equals" not in line
    assert "--env '***'" in line


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

    assert CHECK.id == DRIFT_CHECK_ID


def test_read_sarif_returns_none_when_absent(tmp_path: Path) -> None:
    assert read_sarif(tmp_path / "missing.sarif") is None


def test_read_sarif_returns_none_for_truncated_json(tmp_path: Path) -> None:
    """Finding 3: a runner timeout/OOM can kill the CLI mid-write."""
    path = tmp_path / "broken.sarif"
    path.write_text('{"version": "2.1.0", "runs": [', encoding="utf-8")
    assert read_sarif(path) is None


def test_read_sarif_returns_none_for_a_json_list(tmp_path: Path) -> None:
    """Valid JSON that isn't an object must not lie about being a SARIF dict."""
    path = tmp_path / "list.sarif"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert read_sarif(path) is None


def test_read_sarif_prints_a_stated_message_for_invalid_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "broken.sarif"
    path.write_text("not json", encoding="utf-8")
    assert read_sarif(path) is None
    out = capsys.readouterr().out
    assert str(path) in out
    assert "not valid JSON" in out
    assert "treating it as no SARIF" in out


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
    out = capsys.readouterr().out
    assert "::error::" in out
    assert "Set the `target` input" in out


def test_malformed_env_line_exits_2_before_the_subprocess_ever_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 1: read_inputs rejects the malformed line before build_argv/
    the CLI ever see it, so the CLI's own unmasking echo can never fire."""
    run = FakeRun(0, _sarif())
    rc = main(environ=_gh(tmp_path, env="A=1\nsecret-token-no-equals"), run=run)
    assert rc == 2
    assert run.calls == []
    out = capsys.readouterr().out
    assert "secret-token-no-equals" not in out
    assert "::error::" in out


def test_stale_sarif_at_a_reused_path_is_not_read_as_this_runs_result(
    tmp_path: Path,
) -> None:
    """Finding 5: a prior invocation's SARIF must not leak into this run's
    outputs when the CLI fails before writing a fresh one."""
    env = _gh(tmp_path)
    stale_path = Path(env["INPUT_SARIF"])
    stale_path.parent.mkdir(parents=True, exist_ok=True)
    stale_path.write_text(json.dumps(_sarif(_result(DRIFT_CHECK_ID))), encoding="utf-8")

    rc = main(environ=env, run=FakeRun(2, None))
    assert rc == 2
    assert not stale_path.exists()
    out = _outputs(tmp_path)
    assert out["drift"] == "none"
    assert out["finding-count"] == "0"
    assert "sarif-file" not in out


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


def test_subprocess_run_missing_executable_prints_error_and_returns_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 4: a missing `agent-perimeter` on PATH must fail closed with
    a stated ::error:: message, not an uncaught FileNotFoundError."""

    def _raise(argv: list[str], check: bool) -> None:  # noqa: ARG001 - matches subprocess.run's shape
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(action_module.subprocess, "run", _raise)
    rc = _subprocess_run(["agent-perimeter", "scan"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "::error::" in out
    assert "agent-perimeter" in out


def test_render_summary_counts_by_severity_and_shows_revision() -> None:
    inputs = read_inputs(_env())
    sarif = _sarif(_result("a", "error"), _result("b", "warning"), _result("c", "warning"))
    text = render_summary(inputs, sarif, first_run=False, rc=0)
    assert "| Revision claimed | 2026-07-28 |" in text
    assert "| error | 1 |" in text and "| warning | 2 |" in text
    assert "| Drift | false |" in text
    assert "attacker-authored" not in text
