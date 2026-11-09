"""Agent Perimeter: security posture scanner for MCP servers and tool-using agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    # One source of truth: [project].version in pyproject.toml, as installed.
    __version__ = version("agent-perimeter-scan")
except PackageNotFoundError:  # a bare source tree that was never installed
    __version__ = "0+unknown"
