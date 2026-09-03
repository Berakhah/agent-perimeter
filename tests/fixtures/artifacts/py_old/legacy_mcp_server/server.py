"""Synthetic MCP server source for detect.py's tests.

Not a real package. The pinned SDK (mcp>=1.4.0, see ../pyproject.toml)
predates the 2026-07-28 revision, but this source string-matches the newer
"server/discover" method name anyway - the disagreement detect.py's
SDK-floor rule exists to catch: a package cannot serve what its pinned
dependency cannot express, no matter what its own source mentions.
"""

from __future__ import annotations


def route(method: str) -> str | None:
    if method == "server/discover":
        return "not implemented in this old build"
    return None
