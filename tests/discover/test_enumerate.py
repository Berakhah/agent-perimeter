from agent_perimeter.discover.enumerate import ToolRecord, enumerate_tools
from agent_perimeter.transport.base import TransportError


class FakeTransport:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self._responses = responses

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        if method not in self._responses:
            msg = f"Method not found: {method}"
            raise TransportError(msg)
        return self._responses[method]

    def close(self) -> None: ...


LISTING: dict[str, object] = {
    "tools": [
        {
            "name": "read_file",
            "description": "Read a file.",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            "annotations": {"readOnlyHint": True},
        },
        {"name": "bare"},
    ]
}


def test_tools_are_parsed_into_records() -> None:
    tools = enumerate_tools(FakeTransport({"tools/list": LISTING}))
    assert [t.name for t in tools] == ["read_file", "bare"]
    assert tools[0].description == "Read a file."
    assert tools[0].annotations == {"readOnlyHint": True}


def test_missing_optional_fields_default_empty() -> None:
    tools = enumerate_tools(FakeTransport({"tools/list": LISTING}))
    assert tools[1].description == ""
    assert tools[1].input_schema == {}
    assert tools[1].annotations == {}


def test_entries_without_a_name_are_dropped() -> None:
    tools = enumerate_tools(FakeTransport({"tools/list": {"tools": [{"description": "x"}]}}))
    assert tools == []


def test_unavailable_listing_yields_no_tools_rather_than_raising() -> None:
    assert enumerate_tools(FakeTransport({})) == []


def test_tool_record_construction() -> None:
    record = ToolRecord(name="a", description="", input_schema={}, annotations={})
    assert record.name == "a"
