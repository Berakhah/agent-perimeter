import httpx
import pytest

from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.legacy_sse import DEPRECATED_SINCE, LegacySseTransport

CONTACT = "https://example.test/agent-perimeter"


def _transport(handler: object) -> LegacySseTransport:
    transport = LegacySseTransport("https://mcp.example.test/sse", contact_url=CONTACT)
    transport._client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return transport


def test_construction_warns_that_the_transport_is_deprecated() -> None:
    with pytest.warns(DeprecationWarning, match=DEPRECATED_SINCE):
        LegacySseTransport("https://mcp.example.test/sse", contact_url=CONTACT)


def test_legacy_initialize_round_trip() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25"}},
        )

    result = _transport(handler).request("initialize")
    assert result["protocolVersion"] == "2025-11-25"


def test_no_2026_headers_are_sent() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "mcp-method" not in seen
    assert CONTACT in seen["user-agent"]


def test_error_status_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(TransportError, match="500"):
        _transport(handler).request("tools/list")


def test_malformed_json_body_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"{not valid json", headers={"content-type": "application/json"}
        )

    with pytest.raises(TransportError, match="not valid JSON"):
        _transport(handler).request("tools/list")


def test_deeply_nested_json_body_raises_transport_error_not_recursion_error() -> None:
    """A hostile legacy server can send arbitrarily nested JSON to crash the
    scanner process instead of just failing this one request."""
    nesting = 20000

    def handler(request: httpx.Request) -> httpx.Response:
        body = b"[" * nesting + b"]" * nesting
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    with pytest.raises(TransportError):
        _transport(handler).request("tools/list")


def test_non_dict_json_body_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"])

    with pytest.raises(TransportError, match="not a JSON object"):
        _transport(handler).request("tools/list")


def test_non_dict_result_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": ["not", "a", "dict"]})

    with pytest.raises(TransportError, match="non-object result"):
        _transport(handler).request("tools/list")


def test_header_body_divergence_probe_is_refused_not_forwarded() -> None:
    """`_ap_header_override` is a Streamable-HTTP-only capability. Forwarding
    it as an ordinary JSON-RPC param would make a tolerant server's normal
    result read as "the mismatched body was honoured" — a HIGH-severity false
    positive. The transport boundary fails closed instead."""
    sent: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    with pytest.raises(TransportError, match="header/body divergence"):
        _transport(handler).request("tools/list", {"_ap_header_override": "tools/call"})
    assert sent == [], "the probe must never reach the server"
