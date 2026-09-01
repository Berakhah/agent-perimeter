"""What a tool can do, and how we came to believe it.

An edge inferred from prose is not the same claim as an edge confirmed by a
probe. B9: a confident wrong graph in front of a CISO ends the engagement, so
derivation travels with every edge and the UI renders the three differently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agent_perimeter._contracts import Claim, Derivation


class Capability(StrEnum):
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    NET_OUT = "net_out"
    EXEC = "exec"
    SECRET_READ = "secret_read"
    DB_READ = "db_read"
    DB_WRITE = "db_write"


@dataclass(frozen=True)
class CapabilityEdge:
    tool: str
    capability: Capability
    derivation: Derivation
    claim: Claim
    rationale: str
