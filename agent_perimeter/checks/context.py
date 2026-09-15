"""Everything a check is allowed to see.

`raw` holds unparsed responses keyed by JSON-RPC method, so a check can assert
on protocol fields the parsed models drop, and quote what the server actually
sent as evidence, without re-requesting.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.drift import DriftEvent
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile
from agent_perimeter.model.snapshot import ToolSnapshot
from agent_perimeter.transport.base import Transport, has_header_override
from agent_perimeter.transport.revision import Fingerprint

# The only JSON-RPC methods a check that has not been cleared for active
# probing may reach -- pure enumeration/observation, exactly what
# `transport.revision.fingerprint()` and `discover.enumerate` already call
# without a scope file. An allowlist, not a denylist: a future check calling
# an unrecognised or state-changing method (a tool invocation, a resource
# write) is blocked by default here too, not just the one probe param this
# codebase happens to have today.
PASSIVE_METHODS = frozenset({"server/discover", "initialize", "tools/list"})


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
    baseline: ToolSnapshot | None = None
    """The earlier snapshot of this target the runner compared against, if any."""
    drift_events: tuple[DriftEvent, ...] = ()
    """Computed once by the runner; `drift.description_drift` formats these,
    it never re-computes them."""

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


@dataclass(frozen=True)
class _UnauthorisedTransport:
    """Blocks every non-passive call, for a check that has not been cleared
    for active probing.

    `registry.applicable()` only verifies scope for a check that self-reports
    `requires_auth=True` — trusting that flag. This closes the gap at the
    actual call boundary. An allowlist of passive methods, not a denylist of
    the one probe param this codebase happens to have today: a check that
    declares `requires_auth=False` cannot reach a tool invocation, a resource
    write, or an unrecognised future method either, no matter what its own
    code calls — matching hard constraint 1 (no active probe without scope).
    """

    _inner: Transport

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method not in PASSIVE_METHODS or has_header_override(params):
            msg = (
                f"{method!r} is not a passive method and this check does not "
                "declare requires_auth=True."
            )
            # Not a scope-file field: this check declared requires_auth=False
            # and is not entitled to any active-probe call at all, regardless
            # of scope. Named after the flag it violated, for the same
            # "structured, not regexed" reason require_scope's four sites are.
            raise AuthorizationRequired(msg, missing_field="requires_auth")
        return self._inner.request(method, params)

    def close(self) -> None:
        self._inner.close()
