import logging

import pytest

from agent_perimeter.discover.enumerate import MAX_TOOL_PAGES, ToolRecord, enumerate_tools
from agent_perimeter.transport.base import TransportError


class FakeTransport:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self._responses = responses

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
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


# --- pagination (FU-2) -------------------------------------------------------


class PagedTransport:
    """tools/list pages keyed by cursor; a missing key raises TransportError."""

    def __init__(self, pages: dict[str | None, dict[str, object]]) -> None:
        self.pages = pages
        self.cursors: list[str | None] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        assert method == "tools/list"
        cursor = params.get("cursor") if params else None
        self.cursors.append(cursor if isinstance(cursor, str) else None)
        if cursor not in self.pages:
            msg = "page unavailable"
            raise TransportError(msg)
        return self.pages[cursor]

    def close(self) -> None: ...


def test_follows_next_cursor_across_pages() -> None:
    transport = PagedTransport(
        {
            None: {"tools": [{"name": "a"}], "nextCursor": "c2"},
            "c2": {"tools": [{"name": "b"}], "nextCursor": "c3"},
            "c3": {"tools": [{"name": "c"}]},
        }
    )
    assert [t.name for t in enumerate_tools(transport)] == ["a", "b", "c"]
    assert transport.cursors == [None, "c2", "c3"]


def test_later_page_entry_replaces_earlier_keeping_first_seen_order() -> None:
    transport = PagedTransport(
        {
            None: {
                "tools": [{"name": "a", "description": "old"}, {"name": "b"}],
                "nextCursor": "c2",
            },
            "c2": {"tools": [{"name": "a", "description": "new"}]},
        }
    )
    tools = enumerate_tools(transport)
    assert [t.name for t in tools] == ["a", "b"]
    assert tools[0].description == "new"


def test_same_page_duplicate_names_are_both_kept() -> None:
    transport = PagedTransport({None: {"tools": [{"name": "x"}, {"name": "x"}]}})
    assert [t.name for t in enumerate_tools(transport)] == ["x", "x"]


def test_non_string_or_empty_cursor_stops_paging() -> None:
    for bad in (None, "", 7):
        transport = PagedTransport({None: {"tools": [{"name": "a"}], "nextCursor": bad}})
        assert [t.name for t in enumerate_tools(transport)] == ["a"]
        assert transport.cursors == [None]


def test_repeated_cursor_stops_paging() -> None:
    transport = PagedTransport(
        {
            None: {"tools": [{"name": "a"}], "nextCursor": "loop"},
            "loop": {"tools": [{"name": "b"}], "nextCursor": "loop"},
        }
    )
    assert [t.name for t in enumerate_tools(transport)] == ["a", "b"]
    assert transport.cursors == [None, "loop"]


def test_page_cap_stops_endless_distinct_cursors() -> None:
    class Endless:
        def __init__(self) -> None:
            self.calls = 0

        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            self.calls += 1
            return {"tools": [{"name": f"t{self.calls}"}], "nextCursor": f"c{self.calls}"}

        def close(self) -> None: ...

    transport = Endless()
    tools = enumerate_tools(transport)
    assert transport.calls == MAX_TOOL_PAGES
    assert len(tools) == MAX_TOOL_PAGES


def test_early_stop_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    transport = PagedTransport(
        {
            None: {"tools": [], "nextCursor": "loop"},
            "loop": {"tools": [], "nextCursor": "loop"},
        }
    )
    with caplog.at_level(logging.WARNING):
        enumerate_tools(transport)
    assert "repeated" in caplog.text


def test_page_two_transport_error_keeps_page_one_tools() -> None:
    transport = PagedTransport({None: {"tools": [{"name": "a"}], "nextCursor": "gone"}})
    assert [t.name for t in enumerate_tools(transport)] == ["a"]


def test_page_n_failure_is_logged_and_noted(caplog: pytest.LogCaptureFixture) -> None:
    transport = PagedTransport({None: {"tools": [{"name": "a"}], "nextCursor": "gone"}})
    notes: list[str] = []
    with caplog.at_level(logging.WARNING):
        enumerate_tools(transport, notes)
    assert "page 2 failed" in caplog.text
    assert len(notes) == 1
    assert "page 2" in notes[0]
    assert "1 page(s) received" in notes[0]


def test_page_cap_is_logged_and_noted(caplog: pytest.LogCaptureFixture) -> None:
    class Endless:
        calls = 0

        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            self.calls += 1
            return {"tools": [], "nextCursor": f"c{self.calls}"}

        def close(self) -> None: ...

    notes: list[str] = []
    with caplog.at_level(logging.WARNING):
        enumerate_tools(Endless(), notes)
    assert "page cap" in caplog.text or "incomplete" in caplog.text
    assert len(notes) == 1
    assert str(MAX_TOOL_PAGES) in notes[0]


def test_repeat_cursor_note_names_cursor_and_page_count() -> None:
    transport = PagedTransport(
        {None: {"tools": [], "nextCursor": "loop"}, "loop": {"tools": [], "nextCursor": "loop"}}
    )
    notes: list[str] = []
    enumerate_tools(transport, notes)
    assert len(notes) == 1
    assert "'loop'" in notes[0]
    assert "2 page(s)" in notes[0]


def test_clean_listing_adds_no_notes() -> None:
    notes: list[str] = []
    enumerate_tools(PagedTransport({None: {"tools": [{"name": "a"}]}}), notes)
    assert notes == []
