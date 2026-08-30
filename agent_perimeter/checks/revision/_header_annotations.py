"""Walk a tool schema for every x-mcp-header annotation, reachable or not.

x-mcp-header is an annotation on a parameter's own schema, not a property
named x-mcp-header. Its value names the header suffix (Mcp-Param-<Value>).
This module finds every occurrence regardless of nesting, and separately
records whether each was reachable by a pure chain of `properties` keys —
unreachability is itself a finding (header_annotation_unreachable), so the
walker must not skip what it cannot reach.
"""

from __future__ import annotations

from dataclasses import dataclass

COMPOSITION_KEYWORDS = ("oneOf", "anyOf", "allOf", "not", "if", "then", "else", "items")


@dataclass(frozen=True)
class HeaderAnnotation:
    pointer: str
    value: object
    reachable: bool
    type_name: object


def find_header_annotations(schema: dict[str, object]) -> list[HeaderAnnotation]:
    found: list[HeaderAnnotation] = []
    _walk(schema, pointer="#", reachable=True, found=found)
    return found


def _walk(node: object, *, pointer: str, reachable: bool, found: list[HeaderAnnotation]) -> None:
    if not isinstance(node, dict):
        return

    if "x-mcp-header" in node:
        found.append(
            HeaderAnnotation(
                pointer=pointer,
                value=node["x-mcp-header"],
                reachable=reachable,
                type_name=node.get("type"),
            )
        )

    properties = node.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            _walk(child, pointer=f"{pointer}/properties/{name}", reachable=reachable, found=found)

    for keyword in COMPOSITION_KEYWORDS:
        value = node.get(keyword)
        if isinstance(value, list):
            for index, item in enumerate(value):
                _walk(item, pointer=f"{pointer}/{keyword}/{index}", reachable=False, found=found)
        elif isinstance(value, dict):
            _walk(value, pointer=f"{pointer}/{keyword}", reachable=False, found=found)

    if "$ref" in node:
        # A $ref makes the annotation's reachability depend on external
        # resolution the client may or may not do eagerly — never reachable
        # by a pure properties chain. schema_composition (Task 7) separately
        # flags external and recursive $refs; this walker does not resolve
        # local $defs, since an unresolved pointer is itself the evasion.
        pass
