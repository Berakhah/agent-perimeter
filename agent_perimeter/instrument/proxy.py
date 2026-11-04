# agent_perimeter/instrument/proxy.py
"""MCP request handling for the instrument proxy. Socket-free on purpose.

The proxy is an MCP server to the agent and an MCP client (via Transport) to
the target. It injects the canary only into *successful* results of source
tools -- tools find_paths reports as the start of a source->sink path -- so a
tool with no privileged sink behind it is never touched.

Source detection needs every tool, not just the first page: a source on page
two may have its sink on page one. The proxy therefore accumulates records
across all pages before computing sources.
"""

from __future__ import annotations

import threading

from agent_perimeter.checks.injection.path_proof import find_paths
from agent_perimeter.discover.enumerate import MAX_TOOL_PAGES, ToolRecord
from agent_perimeter.graph.build import build_graph
from agent_perimeter.instrument.canary import Canary, new_canary
from agent_perimeter.instrument.recorder import Recorder, redact
from agent_perimeter.transport.base import Transport, TransportError

SERVER_NAME = "agent-perimeter-instrument"


def _error(message_id: object, code: int, text: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}}


def _records_of(listing: dict[str, object]) -> list[ToolRecord]:
    raw = listing.get("tools")
    records: list[ToolRecord] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict) or "name" not in entry:
            continue
        schema = entry.get("inputSchema")
        annotations = entry.get("annotations")
        records.append(
            ToolRecord(
                name=str(entry["name"]),
                description=str(entry.get("description", "")),
                input_schema=schema if isinstance(schema, dict) else {},
                annotations=annotations if isinstance(annotations, dict) else {},
            )
        )
    return records


def _next_cursor(listing: dict[str, object]) -> str | None:
    cursor = listing.get("nextCursor")
    return cursor if isinstance(cursor, str) and cursor else None


def _cursor_of(params: dict[str, object] | None) -> str | None:
    cursor = params.get("cursor") if params else None
    return cursor if isinstance(cursor, str) and cursor else None


def _text_of(result: dict[str, object]) -> str:
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    return "\n".join(str(block.get("text", "")) for block in content if isinstance(block, dict))


class Proxy:
    def __init__(self, upstream: Transport, canary: Canary | None = None) -> None:
        self._upstream = upstream
        self.canary = canary if canary is not None else new_canary()
        self.recorder = Recorder(self.canary)
        self._records: dict[str, ToolRecord] = {}  # accumulated across pages, by name
        self._sources: frozenset[str] = frozenset()
        self._listed = False  # whether any tools/list reply has been absorbed
        self._pending: str | None = None  # nextCursor not yet followed
        self._lock = threading.Lock()  # one session; Transport is not re-entrant

    def handle(self, message: dict[str, object]) -> dict[str, object] | None:
        method = message.get("method")
        if not isinstance(method, str):
            return _error(
                message.get("id"), -32600, "Request has no method. Send a JSON-RPC 2.0 request."
            )
        if "id" not in message:
            return None  # notification: acknowledged, not forwarded (Transport is request/response)
        message_id = message["id"]
        raw_params = message.get("params")
        params = raw_params if isinstance(raw_params, dict) else None
        with self._lock:
            try:
                result = self._dispatch(method, params)
            except TransportError as exc:
                return _error(
                    message_id,
                    exc.code if exc.code is not None else -32603,
                    redact(str(exc), self.canary),
                )
            except Exception as exc:  # noqa: BLE001 -- the HTTP layer must never return a bare 500
                return _error(
                    message_id,
                    -32603,
                    f"Upstream request failed with {type(exc).__name__}: "
                    f"{redact(str(exc), self.canary)}. "
                    "Check that the target server is running and reachable.",
                )
        if isinstance(result, tuple):  # (code, text) from a local validation failure
            return _error(message_id, result[0], result[1])
        return {"jsonrpc": "2.0", "id": message_id, "result": result}

    def _dispatch(
        self, method: str, params: dict[str, object] | None
    ) -> dict[str, object] | tuple[int, str]:
        if method == "initialize":
            requested = params.get("protocolVersion") if params else None
            return {
                "protocolVersion": requested if isinstance(requested, str) else "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
            }
        if method == "tools/list":
            listing = self._upstream.request("tools/list", params)
            self._absorb(listing, _cursor_of(params))
            return listing
        if method == "tools/call":
            return self._call_tool(params)
        return self._upstream.request(method, params)

    def _absorb(self, listing: dict[str, object], cursor: str | None) -> None:
        """Fold one tools/list page into the accumulated listing.

        A reply to a request without a cursor starts a fresh listing; one with
        a cursor adds to it. A later page's entry for a name replaces the
        earlier one.
        """
        if cursor is None:
            self._records = {}
        for record in _records_of(listing):
            self._records[record.name] = record
        self._listed = True
        self._pending = _next_cursor(listing)
        self._sources = frozenset(
            source for source, _ in find_paths(build_graph(list(self._records.values())))
        )

    def _page_through(self, cursor: str | None) -> None:
        """Follow nextCursor from `cursor` (None = first page) until exhausted.

        Stops when a cursor repeats or after MAX_TOOL_PAGES requests, so a server
        that loops or never ends cannot hold the proxy lock indefinitely.
        """
        requested: set[str] = set()
        for _ in range(MAX_TOOL_PAGES):
            params: dict[str, object] | None = {"cursor": cursor} if cursor is not None else None
            listing = self._upstream.request("tools/list", params)
            self._absorb(listing, cursor)
            following = _next_cursor(listing)
            if following is None or following in requested:
                self._pending = None
                return
            requested.add(following)
            cursor = following
        self._pending = None

    def _call_tool(self, params: dict[str, object] | None) -> dict[str, object] | tuple[int, str]:
        name = params.get("name") if params else None
        if params is None or not isinstance(name, str):
            return (
                -32602,
                "tools/call needs a string 'name'. Send params.name with the tool to call.",
            )
        if not self._listed or self._pending is not None:
            self._page_through(self._pending)
        arguments = params.get("arguments", {})
        try:
            result = self._upstream.request("tools/call", params)
        except TransportError as exc:
            # A strict schema may reject the very call that carries the canary;
            # record it anyway, or an agent that obeyed looks clean.
            code = exc.code if exc.code is not None else -32603
            self.recorder.record_call(name, arguments, f"error {code}: {exc}", injected=False)
            raise
        except Exception as exc:
            self.recorder.record_call(
                name, arguments, f"error -32603: {type(exc).__name__}: {exc}", injected=False
            )
            raise
        inject = name in self._sources and result.get("isError") is not True
        self.recorder.record_call(name, arguments, _text_of(result), injected=inject)
        if not inject:
            return result
        content = result.get("content")
        blocks = list(content) if isinstance(content, list) else []
        blocks.append({"type": "text", "text": self.canary.text})
        return {**result, "content": blocks}
