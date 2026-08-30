from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision import (
    header_annotation_invalid,
    header_annotation_type,
    header_annotation_unreachable,
)
from agent_perimeter.checks.revision._header_annotations import find_header_annotations
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(schema: dict[str, object]) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.PARAM_HEADERS}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        tools=[ToolRecord(name="fetch", description="Fetch a resource.", input_schema=schema)],
    )


def _schema(**region_props: object) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {"region": {"type": "string", **region_props}},
    }


# --- find_header_annotations -------------------------------------------------


def test_reachable_annotation_is_found() -> None:
    found = find_header_annotations(_schema(**{"x-mcp-header": "Region"}))
    assert len(found) == 1
    assert found[0].value == "Region"
    assert found[0].reachable is True


def test_annotation_behind_oneof_is_found_but_marked_unreachable() -> None:
    schema = {
        "type": "object",
        "properties": {"region": {"oneOf": [{"type": "string", "x-mcp-header": "Region"}]}},
    }
    found = find_header_annotations(schema)
    assert len(found) == 1
    assert found[0].reachable is False


# --- header_annotation_invalid ------------------------------------------------


def test_empty_annotation_value_is_reported() -> None:
    findings = header_annotation_invalid.CHECK.run(_context(_schema(**{"x-mcp-header": ""})))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_annotation_with_crlf_is_reported() -> None:
    schema = _schema(**{"x-mcp-header": "Region\r\nX-Injected: 1"})
    findings = header_annotation_invalid.CHECK.run(_context(schema))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-113"


def test_annotation_that_is_not_a_token_is_reported() -> None:
    findings = header_annotation_invalid.CHECK.run(_context(_schema(**{"x-mcp-header": "Re gion"})))
    assert len(findings) == 1


def test_duplicate_annotation_values_are_reported() -> None:
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "string", "x-mcp-header": "Region"},
            "b": {"type": "string", "x-mcp-header": "region"},
        },
    }
    findings = header_annotation_invalid.CHECK.run(_context(schema))
    assert len(findings) == 1
    title = findings[0].title.lower()
    assert "case-insensitively" in title or "duplicate" in title


def test_valid_unique_token_annotation_is_clean() -> None:
    schema = _schema(**{"x-mcp-header": "Region"})
    assert header_annotation_invalid.CHECK.run(_context(schema)) == []


# --- header_annotation_unreachable -------------------------------------------


def test_annotation_behind_oneof_is_reported() -> None:
    schema = {
        "type": "object",
        "properties": {"region": {"oneOf": [{"type": "string", "x-mcp-header": "Region"}]}},
    }
    findings = header_annotation_unreachable.CHECK.run(_context(schema))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_reachable_annotation_is_clean_for_unreachable_check() -> None:
    assert (
        header_annotation_unreachable.CHECK.run(_context(_schema(**{"x-mcp-header": "Region"})))
        == []
    )


# --- header_annotation_type ---------------------------------------------------


def test_number_typed_annotation_is_reported() -> None:
    schema = {
        "type": "object",
        "properties": {"region": {"type": "number", "x-mcp-header": "Region"}},
    }
    findings = header_annotation_type.CHECK.run(_context(schema))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_integer_outside_js_safe_range_is_reported() -> None:
    schema = {
        "type": "object",
        "properties": {
            "region": {
                "type": "integer",
                "x-mcp-header": "Region",
                "maximum": 2**53,
            }
        },
    }
    assert len(header_annotation_type.CHECK.run(_context(schema))) == 1


def test_integer_outside_js_safe_range_behind_oneof_is_still_reported() -> None:
    """Regression: the pointer segment addressing a oneOf branch is a list
    index (e.g. .../oneOf/0), not a dict key. _type_violation's manual
    pointer re-walk must follow it into the list, not silently give up and
    report no maximum bound."""
    schema = {
        "type": "object",
        "properties": {
            "region": {
                "oneOf": [
                    {
                        "type": "integer",
                        "x-mcp-header": "Region",
                        "maximum": 2**53,
                    }
                ]
            }
        },
    }
    assert len(header_annotation_type.CHECK.run(_context(schema))) == 1


def test_string_typed_annotation_is_clean_for_type_check() -> None:
    assert header_annotation_type.CHECK.run(_context(_schema(**{"x-mcp-header": "Region"}))) == []


def test_tool_with_no_annotation_is_clean_for_every_check() -> None:
    schema = {"type": "object", "properties": {"path": {"type": "string"}}}
    assert header_annotation_invalid.CHECK.run(_context(schema)) == []
    assert header_annotation_unreachable.CHECK.run(_context(schema)) == []
    assert header_annotation_type.CHECK.run(_context(schema)) == []
