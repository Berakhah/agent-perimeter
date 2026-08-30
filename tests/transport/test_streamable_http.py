import json

import httpx
import pytest

from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

CONTACT = "https://example.test/agent-perimeter"
PROTOCOL_VERSION = "2026-07-28"


def _transport(handler: object) -> StreamableHttpTransport:
    transport = StreamableHttpTransport("https://mcp.example.test/rpc", contact_url=CONTACT)
    transport._client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return transport


def test_meta_is_nested_inside_params_not_a_sibling() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "_meta" not in seen
    params = seen["params"]
    assert isinstance(params, dict)
    meta = params["_meta"]
    assert isinstance(meta, dict)
    assert meta["io.modelcontextprotocol/protocolVersion"] == PROTOCOL_VERSION
    assert "io.modelcontextprotocol/clientCapabilities" in meta


def test_protocol_version_header_matches_the_meta_value() -> None:
    seen_headers: dict[str, str] = {}
    seen_body: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        seen_body.update(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    params = seen_body["params"]
    assert isinstance(params, dict)
    meta = params["_meta"]
    assert isinstance(meta, dict)
    assert seen_headers["mcp-protocol-version"] == meta["io.modelcontextprotocol/protocolVersion"]


def test_mcp_method_equals_the_request_method() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("resources/list")
    assert seen["mcp-method"] == "resources/list"


def test_mcp_name_present_only_for_the_three_named_methods_and_sourced_from_params() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "mcp-name" not in seen

    _transport(handler).request("tools/call", {"name": "read_file"})
    assert seen["mcp-name"] == "read_file"

    _transport(handler).request("resources/read", {"uri": "file:///x"})
    assert seen["mcp-name"] == "file:///x"


def test_no_session_header_is_ever_sent() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "mcp-session-id" not in seen
    assert CONTACT in seen["user-agent"]


def test_sse_response_is_parsed_from_its_final_data_event() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = 'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\n\n'
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    result = _transport(handler).request("tools/list")
    assert result == {"tools": []}


def test_json_rpc_error_is_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}
        )

    with pytest.raises(TransportError, match="nope") as excinfo:
        _transport(handler).request("server/discover")
    assert excinfo.value.code == -32601


def test_http_error_status_is_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    with pytest.raises(TransportError, match="503"):
        _transport(handler).request("tools/list")


def test_modern_header_mismatch_error_code_is_captured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32020, "message": "HeaderMismatch"},
            },
        )

    with pytest.raises(TransportError) as excinfo:
        _transport(handler).request("tools/list")
    assert excinfo.value.code == -32020


def test_malformed_json_body_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"{not valid json", headers={"content-type": "application/json"}
        )

    with pytest.raises(TransportError, match="not valid JSON"):
        _transport(handler).request("tools/list")


def test_non_dict_json_body_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    with pytest.raises(TransportError, match="not a JSON object"):
        _transport(handler).request("tools/list")


def test_non_dict_sse_data_payload_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = 'event: message\ndata: "just a string"\n\n'
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    with pytest.raises(TransportError, match="not a JSON object"):
        _transport(handler).request("tools/list")


def test_malformed_sse_data_payload_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = "event: message\ndata: {not valid json\n\n"
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    with pytest.raises(TransportError, match="malformed JSON"):
        _transport(handler).request("tools/list")


def test_deeply_nested_json_body_raises_transport_error_not_recursion_error() -> None:
    """A hostile server can send arbitrarily nested JSON to crash the scanner
    process instead of just failing this one request."""
    nesting = 20000

    def handler(request: httpx.Request) -> httpx.Response:
        body = b"[" * nesting + b"]" * nesting
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    with pytest.raises(TransportError):
        _transport(handler).request("tools/list")


def test_deeply_nested_sse_payload_raises_transport_error_not_recursion_error() -> None:
    nesting = 20000

    def handler(request: httpx.Request) -> httpx.Response:
        body = "event: message\ndata: " + "[" * nesting + "]" * nesting + "\n\n"
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    with pytest.raises(TransportError):
        _transport(handler).request("tools/list")


def test_header_override_changes_body_method_but_not_the_header() -> None:
    """`_ap_header_override` lets a check send a deliberately inconsistent
    request: `Mcp-Method` stays the outer `method` argument (unchanged), while
    the JSON body's `method` field becomes the override value — the attack
    shape is a benign-looking header routing a dangerous body. The literal
    key `_ap_header_override` must never reach the wire."""
    seen_headers: dict[str, str] = {}
    seen_body: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        seen_body.update(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list", {"_ap_header_override": "tools/call"})

    assert seen_headers["mcp-method"] == "tools/list"
    assert seen_body["method"] == "tools/call"
    assert "_ap_header_override" not in seen_body
    params = seen_body["params"]
    assert isinstance(params, dict)
    assert "_ap_header_override" not in params


def test_non_dict_result_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": ["not", "a", "dict"]})

    with pytest.raises(TransportError, match="non-object result"):
        _transport(handler).request("tools/list")
