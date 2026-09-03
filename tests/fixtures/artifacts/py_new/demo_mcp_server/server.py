"""Synthetic MCP server source for detect.py's tests.

Not a real package - just enough Python for the ast parser to accept and for
the source-signal regexes to match, standing in for a server whose pinned SDK
(mcp>=2.1.0, see ../pyproject.toml) is new enough to actually ship these
handlers.
"""

from __future__ import annotations


def handle_discover() -> dict[str, object]:
    """Registered at the "server/discover" RPC method."""
    return {"capabilities": {}}


def handle_tool_result() -> dict[str, object]:
    """Returns the 2026-07-28 result envelope shape."""
    return {"resultType": "text", "ttlMs": 60000}
