"""Everything a check is allowed to see.

`raw` holds unparsed responses keyed by JSON-RPC method, so a check can assert
on protocol fields the parsed models drop, and quote what the server actually
sent as evidence, without re-requesting.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.scope import ScopeFile
from agent_perimeter.transport.base import Transport
from agent_perimeter.transport.revision import Fingerprint


@dataclass(frozen=True)
class ScanContext:
    target: str
    transport: Transport
    fingerprint: Fingerprint
    tools: list[ToolRecord] = field(default_factory=list)
    raw: dict[str, dict[str, object]] = field(default_factory=dict)
    scope: ScopeFile | None = None
    ambiguous_tools: frozenset[str] = field(default_factory=frozenset)

    def reproduction(self, check_id: str) -> str:
        """The command a sceptic runs to reproduce one finding."""
        return f"agent-perimeter scan --target {self.target} --only {check_id}"
