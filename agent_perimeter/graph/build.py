"""Infer capability edges from independent sources.

Precedence is NAME over DESCRIPTION, because a declared parameter name is
still stronger evidence than a sentence, even though it is not structural
schema evidence. PROBE edges are added by the active checks in Tasks 3-6 and
always win, since they are confirmations rather than inferences.

Derivation.SCHEMA is reserved for genuine structural evidence -- format: uri,
enum, pattern, declared types, MCP annotations, the x-mcp-header annotation --
none of which this module currently inspects. Matching a parameter's *name*
against a regex is Derivation.NAME: real evidence, but weaker than structure,
and tagged with confidence < 1.0 so it renders differently. Tagging a name
match SCHEMA is exactly B9's "confidently wrong" pattern in the screen the
deck leads with (revision §3, §7.4).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.edge import Capability, CapabilityEdge

# A name match, not a schema fact -- Derivation.NAME, not Derivation.SCHEMA.
# fs_write has no entry here at all (only a DESCRIPTION-level signal below);
# db_write has no entry in either list. Both are stated gaps: a missing edge
# is the honest outcome for a capability with no evidence behind it.
NAME_SIGNALS: tuple[tuple[re.Pattern[str], Capability], ...] = (
    (re.compile(r"^(path|file|filename|filepath|dir|directory)$", re.I), Capability.FS_READ),
    (re.compile(r"^(url|uri|endpoint|host|webhook|callback)$", re.I), Capability.NET_OUT),
    (re.compile(r"^(command|cmd|script|shell|exec|argv)$", re.I), Capability.EXEC),
    (re.compile(r"^(query|sql|statement)$", re.I), Capability.DB_READ),
    (re.compile(r"(token|secret|api[_-]?key|credential)", re.I), Capability.SECRET_READ),
)

DESCRIPTION_SIGNALS: tuple[tuple[re.Pattern[str], Capability], ...] = (
    (re.compile(r"\b(read|open|load)s?\b.{0,20}\bfile\b", re.I), Capability.FS_READ),
    (re.compile(r"\b(write|save|store)s?\b.{0,20}\b(file|disk)\b", re.I), Capability.FS_WRITE),
    (
        re.compile(r"\b(fetch|request|send|post|upload)s?\b.{0,30}\b(url|api|endpoint|http)", re.I),
        Capability.NET_OUT,
    ),
    (
        re.compile(
            r"\b(run|execute|spawn)s?\b.{0,20}\b(command|shell|process)\b",
            re.I,
        ),
        Capability.EXEC,
    ),
    (re.compile(r"\b(quer|select)\w*\b.{0,20}\bdatabase\b", re.I), Capability.DB_READ),
)

# Name matches and description matches both fall short of confirmation --
# 0.5 for a declared identifier, 0.4 for a sentence, are placeholders pending
# real calibration (00 B10), not measured numbers.
_CONFIDENCE: dict[Derivation, float] = {
    Derivation.NAME: 0.5,
    Derivation.DESCRIPTION: 0.4,
}
_CAVEAT: dict[Derivation, str] = {
    Derivation.NAME: "Inferred from a parameter name match, not schema structure or a probe",
    Derivation.DESCRIPTION: "Inferred from prose; not confirmed by probe",
}


def _claim(derivation: Derivation, value: str) -> Claim:
    return Claim(
        value=value,
        method=Method.DETERMINISTIC,
        derivation=derivation,
        observed_at=datetime.now(UTC),
        caveat=_CAVEAT.get(derivation),
        confidence=_CONFIDENCE.get(derivation),
    )


def build_graph(tools: list[ToolRecord]) -> list[CapabilityEdge]:
    edges: list[CapabilityEdge] = []

    for tool in tools:
        found: dict[Capability, CapabilityEdge] = {}

        properties = tool.input_schema.get("properties")
        if isinstance(properties, dict):
            for name in properties:
                for pattern, capability in NAME_SIGNALS:
                    if not pattern.search(str(name)):
                        continue
                    found[capability] = CapabilityEdge(
                        tool=tool.name,
                        capability=capability,
                        derivation=Derivation.NAME,
                        claim=_claim(Derivation.NAME, f"{tool.name}:{capability.value}"),
                        rationale=f"input schema declares a parameter named {name!r}",
                    )

        for pattern, capability in DESCRIPTION_SIGNALS:
            if capability in found:
                continue
            match = pattern.search(tool.description)
            if match is None:
                continue
            found[capability] = CapabilityEdge(
                tool=tool.name,
                capability=capability,
                derivation=Derivation.DESCRIPTION,
                claim=_claim(Derivation.DESCRIPTION, f"{tool.name}:{capability.value}"),
                rationale=f"description says {match.group(0)!r}",
            )

        edges.extend(found.values())

    return edges
