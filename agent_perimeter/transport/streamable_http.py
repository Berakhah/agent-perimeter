"""Streamable HTTP transport for MCP 2026-07-28.

Protocol-level sessions and the Mcp-Session-Id header were removed in this
revision, so nothing here carries session state. `_meta` lives inside
`params`, not beside it. Every POST carries an `MCP-Protocol-Version` header
matching `_meta`'s protocol version — a server MUST reject a mismatch with
`400` + `HeaderMismatch` (`-32020`). `Mcp-Method` always equals `method`;
`Mcp-Name` is sourced from the request's own `params.name` or `params.uri`
and sent only for `tools/call`, `resources/read`, `prompts/get` — sending it
on every request is itself the header/body mismatch a conforming server
rejects. A response MAY arrive as `text/event-stream` instead of a single
JSON body; the final `data:` event is the JSON-RPC response.
"""

from __future__ import annotations

import json

import httpx

from agent_perimeter.transport.base import TransportError

CLIENT_NAME = "agent-perimeter"
CLIENT_VERSION = "0.1.0"
PROTOCOL_VERSION = "2026-07-28"
NAMED_METHODS = {"tools/call", "resources/read", "prompts/get"}


def _mcp_name(method: str, params: dict[str, object] | None) -> str | None:
    """Mcp-Name is required only for the three named methods, sourced from
    the request's own params — never the client's own name."""
    if method not in NAMED_METHODS or not params:
        return None
    name = params.get("name", params.get("uri"))
    return str(name) if name is not None else None


def _error_code(response: httpx.Response) -> int | None:
    try:
        payload = response.json()
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, int) else None


def _parse_sse(text: str) -> dict[str, object]:
    """A server MAY answer any request with an SSE stream. Take the final
    `data:` event as the JSON-RPC response."""
    data_lines = [
        line[len("data:") :].strip() for line in text.splitlines() if line.startswith("data:")
    ]
    if not data_lines:
        msg = "SSE response contained no data: event"
        raise TransportError(msg)
    try:
        result = json.loads(data_lines[-1])
    except (ValueError, TypeError, RecursionError) as exc:
        msg = "SSE response contained malformed JSON in its final data: event"
        raise TransportError(msg) from exc
    if not isinstance(result, dict):
        msg = "SSE response's final data: event was not a JSON object"
        raise TransportError(msg)
    return result


def _parse_body(response: httpx.Response) -> dict[str, object]:
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        return _parse_sse(response.text)
    try:
        result = response.json()
    except (ValueError, RecursionError) as exc:
        msg = f"{response.status_code} response body was not valid JSON"
        raise TransportError(msg) from exc
    if not isinstance(result, dict):
        msg = "Response body was not a JSON object"
        raise TransportError(msg)
    return result


class StreamableHttpTransport:
    def __init__(self, url: str, *, timeout_s: float = 30.0, contact_url: str) -> None:
        self._url = url
        self._client = httpx.Client(timeout=timeout_s)
        self._contact_url = contact_url

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        request_params = dict(params or {})
        request_params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": CLIENT_NAME,
                "version": CLIENT_VERSION,
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": request_params,
        }
        headers = {
            "Mcp-Method": method,
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION} (+{self._contact_url})",
        }
        name = _mcp_name(method, params)
        if name is not None:
            headers["Mcp-Name"] = name

        response = self._client.post(self._url, json=body, headers=headers)
        if response.status_code >= 400:
            msg = f"{self._url} returned {response.status_code} for {method}."
            raise TransportError(msg, code=_error_code(response))

        message = _parse_body(response)
        if "error" in message:
            error = message["error"]
            code = error.get("code") if isinstance(error, dict) else None
            msg = f"Server returned an error for {method}: {error}"
            raise TransportError(msg, code=code if isinstance(code, int) else None)
        result = message.get("result", {})
        if not isinstance(result, dict):
            msg = f"Server returned a non-object result for {method}"
            raise TransportError(msg)
        return result

    def close(self) -> None:
        self._client.close()
