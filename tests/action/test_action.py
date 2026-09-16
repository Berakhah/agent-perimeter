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
