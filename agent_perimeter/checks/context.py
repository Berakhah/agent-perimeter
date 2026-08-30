"""Everything a check is allowed to see.

`raw` holds unparsed responses keyed by JSON-RPC method, so a check can assert
on protocol fields the parsed models drop, and quote what the server actually
sent as evidence, without re-requesting.
"""

from __future__ import annotations

import shlex
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
    invocation_flags: tuple[str, ...] = ()
    """The flags this scan was actually invoked with, already shell-quoted —
    only those the operator genuinely supplied, never fabricated. Without
    them `--only secrets.config_scan` re-runs with no `--config` and finds
    nothing, and `--only revision.header_body_mismatch` re-runs in passive
    mode and reports NOT_AUTHORISED. Populated by cli.py's `scan`."""

    def reproduction(self, check_id: str) -> str:
        """The command a sceptic runs to reproduce one finding.

        `target` is shell-quoted: a stdio target is a command line ("python
        server.py"), and a URL target routinely carries `?` and `&`, both of
        which a shell would act on rather than pass through.
        """
        parts = [
            "agent-perimeter scan",
            f"--target {shlex.quote(self.target)}",
            f"--only {check_id}",
            *self.invocation_flags,
        ]
        return " ".join(parts)
