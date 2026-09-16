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
