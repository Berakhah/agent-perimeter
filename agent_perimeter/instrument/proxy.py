# agent_perimeter/instrument/proxy.py
"""MCP request handling for the instrument proxy. Socket-free on purpose.

The proxy is an MCP server to the agent and an MCP client (via Transport) to
the target. It injects the canary only into *successful* results of source
tools -- tools find_paths reports as the start of a source->sink path -- so a
tool with no privileged sink behind it is never touched.
"""

from __future__ import annotations

import threading

from agent_perimeter.checks.injection.path_proof import find_paths
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.graph.build import build_graph
from agent_perimeter.instrument.canary import Canary, new_canary
from agent_perimeter.instrument.recorder import Recorder
from agent_perimeter.transport.base import Transport, TransportError

SERVER_NAME = "agent-perimeter-instrument"


def _error(message_id: object, code: int, text: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}}


def _source_names(listing: dict[str, object]) -> frozenset[str]:
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
    return frozenset(source for source, _ in find_paths(build_graph(records)))


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
        self._sources: frozenset[str] | None = None
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
                return _error(message_id, exc.code if exc.code is not None else -32603, str(exc))
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
            self._sources = _source_names(listing)
            return listing
        if method == "tools/call":
            return self._call_tool(params)
        return self._upstream.request(method, params)

    def _call_tool(self, params: dict[str, object] | None) -> dict[str, object] | tuple[int, str]:
        name = params.get("name") if params else None
        if params is None or not isinstance(name, str):
            return (
                -32602,
                "tools/call needs a string 'name'. Send params.name with the tool to call.",
            )
        if self._sources is None:
            self._sources = _source_names(self._upstream.request("tools/list"))
        result = self._upstream.request("tools/call", params)
        inject = name in self._sources and result.get("isError") is not True
        self.recorder.record_call(
            name, params.get("arguments", {}), _text_of(result), injected=inject
        )
        if not inject:
            return result
        content = result.get("content")
        blocks = list(content) if isinstance(content, list) else []
        blocks.append({"type": "text", "text": self.canary.text})
        return {**result, "content": blocks}
