"""The version a report claims is the version that produced it.

SARIF `tool.driver.version` and a scan row's `tool_version` are how a reader matches a finding
to the scanner build behind it. A literal in a call site drifts the moment pyproject.toml is
bumped (it did: reports said 0.1.0 while the Action was at v1.1.0).
"""

from __future__ import annotations

import ast
from importlib.metadata import version
from pathlib import Path

import agent_perimeter

PACKAGE = Path(agent_perimeter.__file__).parent


def test_dunder_version_is_the_installed_distribution_version() -> None:
    assert agent_perimeter.__version__ == version("agent-perimeter")


def test_no_call_site_hardcodes_a_tool_version() -> None:
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.keyword)
                and node.arg == "tool_version"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                offenders.append(f"{path.relative_to(PACKAGE.parent)}:{node.value.lineno}")
    assert offenders == [], f"use agent_perimeter.__version__ instead: {offenders}"
