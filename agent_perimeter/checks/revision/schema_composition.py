"""Dangerous $ref usage in the newly-loosened tool schemas.

SEP-2106 allows any JSON Schema 2020-12 keyword in inputSchema, including $ref
resolution and composition. An external $ref makes every resolving client fetch
a server-nominated URL; a self-referential $ref chain is unbounded recursion
against clients that resolve eagerly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

# Revision 5.1: bounds the spec asks implementations to apply, so a malicious
# schema cannot exhaust this validator the way it would an unbounded one.
MAX_SCHEMA_DEPTH = 64
MAX_SUBSCHEMA_COUNT = 2000
MAX_TOTAL_NODES = 5000

METADATA_ADDRESSES = ("169.254.169.254", "metadata.google.internal")
EXTERNAL_SCHEMES = ("http://", "https://", "file://", "ftp://", "ws://", "wss://", "//")


class SchemaBoundExceeded(Exception):
    """Raised internally when a walk exceeds a bound; caught by the caller,
    never allowed to propagate as a raw RecursionError/MemoryError would."""

    def __init__(self, kind: str, limit: int) -> None:
        super().__init__(f"{kind} exceeded bound {limit}")
        self.kind = kind
        self.limit = limit


def _resolve_local_pointer(root: object, ref: str) -> object | None:
    """Resolve a same-document JSON Pointer (RFC 6901) fragment against `root`.

    Never touches the network: a `#`-fragment ref is a same-document
    reference by definition, so this is plain dict/list indexing. Returns
    None for a pointer that does not resolve, rather than raising — a
    dangling local ref is not this function's concern.
    """
    pointer = ref[1:]  # drop leading "#"
    if pointer.startswith("/"):
        pointer = pointer[1:]
    if pointer == "":
        return root
    current: object = root
    for raw_segment in pointer.split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif isinstance(current, list):
            try:
                index = int(segment)
            except ValueError:
                return None
            if not 0 <= index < len(current):
                return None
            current = current[index]
        else:
            return None
    return current


class _RefClosed:
    """Sentinel pushed onto the walk stack right after a local ref's target:
    since the stack is genuinely LIFO-depth-first (a subtree's entire
    descendants are drained before its earlier sibling is popped), this
    marker is only popped once that whole subtree has been fully walked —
    the classic iterative-postorder trick, giving `_collect_refs` a
    white/gray/black coloring of ref pointers without ever recursing."""

    __slots__ = ("ref",)

    def __init__(self, ref: str) -> None:
        self.ref = ref


def _collect_refs(node: object, found: list[str]) -> None:
    """Iterative, explicit-stack walk. No Python call recursion, ever.

    Enforces MAX_SCHEMA_DEPTH, MAX_SUBSCHEMA_COUNT and MAX_TOTAL_NODES as it
    goes, raising SchemaBoundExceeded (never RecursionError) the moment one is
    crossed — the caller turns that into a finding about the target, per
    revision 5.1's "containment event" framing, not a silent truncation.

    A local ("#/...") ref is resolved against the document root and walked.
    `ref_state` tracks each local pointer as "in_progress" (currently on the
    walk's own ancestor chain — seeing it again *is* a genuine cycle, caught
    immediately via SchemaBoundExceeded, CWE-674) or "done" (its subtree was
    already walked once, found clean, and is never re-walked or re-counted).
    Without that second state, heavy legitimate reuse of one small $defs
    entry from hundreds of unrelated properties — not a cycle, just a shared
    type — would eventually trip the node/subschema-count bounds and read as
    a false-positive DoS finding, which is exactly the failure mode this
    project's own testing bar treats as worse than a gap. A real JSON Schema
    validator resolves each $defs entry once and caches it; this mirrors
    that. An external ref is only ever collected as a string here, never
    resolved — no network URI is followed.
    """
    root = node
    stack: list[tuple[object, int]] = [(node, 0)]
    subschema_count = 0
    total_nodes = 0
    ref_state: dict[str, str] = {}

    while stack:
        current, depth = stack.pop()
        if isinstance(current, _RefClosed):
            ref_state[current.ref] = "done"
            continue

        total_nodes += 1
        if total_nodes > MAX_TOTAL_NODES:
            raise SchemaBoundExceeded("total node count", MAX_TOTAL_NODES)
        if depth > MAX_SCHEMA_DEPTH:
            raise SchemaBoundExceeded("schema depth", MAX_SCHEMA_DEPTH)

        if isinstance(current, dict):
            subschema_count += 1
            if subschema_count > MAX_SUBSCHEMA_COUNT:
                raise SchemaBoundExceeded("subschema count", MAX_SUBSCHEMA_COUNT)
            ref = current.get("$ref")
            if isinstance(ref, str):
                found.append(ref)
                if ref.startswith("#"):
                    state = ref_state.get(ref)
                    if state == "in_progress":
                        raise SchemaBoundExceeded("self-referential $ref", 1)
                    if state is None:
                        target = _resolve_local_pointer(root, ref)
                        if target is not None:
                            ref_state[ref] = "in_progress"
                            stack.append((_RefClosed(ref), depth))
                            stack.append((target, depth + 1))
            for value in current.values():
                stack.append((value, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))


def _is_external(ref: str) -> bool:
    lowered = ref.lower()
    return lowered.startswith(EXTERNAL_SCHEMES)


def _is_metadata_address(ref: str) -> bool:
    lowered = ref.lower()
    return any(address in lowered for address in METADATA_ADDRESSES)


@dataclass(frozen=True)
class SchemaCompositionCheck:
    id: str = "revision.schema_composition"
    cwe: str = "CWE-674"
    taxonomy_refs: tuple[str, ...] = ("mcp-spec:2026-07-28-changelog", "owasp-llm:LLM06")
    severity: Severity = Severity.HIGH
    requires_auth: bool = False
    requires_model: bool = False
    # No feature gate: this check is purely structural over tool.input_schema
    # and $ref/composition keywords can appear regardless of which optional
    # protocol features a server negotiates (see task correction: there is no
    # Feature.STATELESS_META — that would describe the client's request
    # shape, not something the server does).
    requires_features: frozenset[Feature] = field(default_factory=frozenset)

    def run(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in context.tools:
            refs: list[str] = []
            try:
                _collect_refs(tool.input_schema, refs)
            except SchemaBoundExceeded as exc:
                # This *is* the recursion / DoS-shape finding now — a genuine
                # cycle is caught the moment a $ref reappears on its own
                # ancestor chain, and any other bound exceeded during the
                # walk cannot be evaded by restructuring the $ref chain the
                # way pattern-matching for a cycle could.
                if exc.kind == "self-referential $ref":
                    title = f"Tool {tool.name!r} schema contains a self-referential $ref cycle"
                else:
                    title = (
                        f"Tool {tool.name!r} schema exceeds the {exc.kind} bound "
                        f"({exc.limit}) — a Denial-of-Service shape the "
                        f"specification asks implementations to bound"
                    )
                findings.append(
                    self._finding(context, tool.name, f"{exc.kind}={exc.limit}", title, "CWE-674")
                )
                continue
            for ref in refs:
                if _is_metadata_address(ref):
                    findings.append(
                        self._finding(
                            context,
                            tool.name,
                            ref,
                            f"Tool {tool.name!r} schema resolves a $ref to a cloud metadata "
                            "address",
                            "CWE-918",
                            severity=Severity.CRITICAL,
                        )
                    )
                elif _is_external(ref):
                    findings.append(
                        self._finding(
                            context,
                            tool.name,
                            ref,
                            f"Tool {tool.name!r} schema resolves an external $ref",
                            "CWE-918",
                        )
                    )
        return findings

    def _finding(
        self,
        context: ScanContext,
        tool: str,
        ref: str,
        title: str,
        cwe: str,
        *,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity or self.severity,
            title=title,
            cwe=cwe,
            taxonomy_refs=self.taxonomy_refs,
            evidence=Evidence(
                kind=EvidenceKind.EXCERPT, excerpt=json.dumps({"$ref": ref}, indent=2)
            ),
            reproduction=context.reproduction(self.id),
            claim=Claim(
                value=f"{tool}:{ref}",
                method=Method.DETERMINISTIC,
                derivation=Derivation.SCHEMA,
                observed_at=datetime.now(UTC),
            ),
        )


CHECK = SchemaCompositionCheck()
