"""Shared machinery for authorisation-gated active probes.

Two rules govern everything in this package.

No probe runs without a scope file. The registry already gates requires_auth
checks, and every probe re-asserts it at the point of use, because a guard that
exists in exactly one place is a guard a refactor can delete silently.

No probe weaponises anything. A probe proves reachability and stops. Path
traversal reads a benign canary and reports the path; it never touches a system
file and never exfiltrates.
"""

from __future__ import annotations

from datetime import date

from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.scope import require_scope

CANARY_PATH = "../../tmp/agent-perimeter-canary.txt"
CANARY_CONTENT = "AGENT-PERIMETER-CANARY-DO-NOT-REMOVE"
CANARY_MARKER = "AGENT-PERIMETER-CANARY"
CANARY_URL = "http://127.0.0.1:9/agent-perimeter-canary"


def assert_authorised(context: ScanContext, check_id: str) -> None:
    """Re-assert authorisation at the point of use."""
    require_scope(context.scope, check_id=check_id, target=context.target, today=date.today())


def call_tool(context: ScanContext, tool: str, arguments: dict[str, object]) -> dict[str, object]:
    return context.transport.request("tools/call", {"name": tool, "arguments": arguments})


def response_text(result: dict[str, object]) -> str:
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            parts.append(str(item["text"]))
    return "\n".join(parts)
