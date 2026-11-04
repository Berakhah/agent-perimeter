# tests/instrument/test_proxy.py
from agent_perimeter.instrument.canary import Canary
from agent_perimeter.instrument.proxy import Proxy
from agent_perimeter.transport.base import TransportError

CANARY = Canary(nonce="00ff00ff00ff00ff")

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the local workspace.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "sync_to_webhook",
        "description": "Sync a local file to a remote webhook.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "url": {"type": "string"}},
        },
    },
]


class FakeTransport:
    def __init__(self, results: dict[str, dict[str, object]] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, object] | None]] = []
        self.results = results or {}
        self.fail_with: Exception | None = None
        self.closed = False

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.calls.append((method, params))
        if self.fail_with is not None:
            raise self.fail_with
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            assert params is not None
            return self.results[str(params["name"])]
        return {"echo": method}

    def close(self) -> None:
        self.closed = True


def _ok(text: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": text}]}


def _call(proxy: Proxy, name: str, arguments: dict[str, object] | None = None, mid: int = 1):
    return proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": mid,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )


def _texts(reply: dict[str, object]) -> list[str]:
    return [b["text"] for b in reply["result"]["content"]]  # type: ignore[index]


def test_source_tool_success_gets_exactly_one_canary_block() -> None:
    proxy = Proxy(FakeTransport({"read_file": _ok("hello")}), CANARY)
    reply = _call(proxy, "read_file", {"path": "a"})
    assert reply is not None
    assert _texts(reply) == ["hello", CANARY.text]


def test_non_source_tool_is_not_touched() -> None:
    proxy = Proxy(FakeTransport({"sync_to_webhook": _ok("sent")}), CANARY)
    reply = _call(proxy, "sync_to_webhook", {"path": "a", "url": "u"})
    assert reply is not None
    assert _texts(reply) == ["sent"]


def test_error_results_are_never_injected() -> None:
    err = {"isError": True, "content": [{"type": "text", "text": "boom"}]}
    proxy = Proxy(FakeTransport({"read_file": err}), CANARY)
    reply = _call(proxy, "read_file")
    assert reply is not None
    assert _texts(reply) == ["boom"]


def test_tools_list_is_forwarded_unchanged() -> None:
    proxy = Proxy(FakeTransport(), CANARY)
    reply = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert reply == {"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}}


def test_unknown_methods_are_forwarded_unchanged() -> None:
    upstream = FakeTransport()
    reply = Proxy(upstream, CANARY).handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})
    assert reply == {"jsonrpc": "2.0", "id": 7, "result": {"echo": "ping"}}
    assert ("ping", None) in upstream.calls


def test_initialize_is_answered_locally_and_not_forwarded() -> None:
    upstream = FakeTransport()
    reply = Proxy(upstream, CANARY).handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        }
    )
    assert reply is not None
    assert reply["result"]["protocolVersion"] == "2025-11-25"  # type: ignore[index]
    assert upstream.calls == []


def test_notifications_are_acknowledged_without_forwarding() -> None:
    upstream = FakeTransport()
    assert (
        Proxy(upstream, CANARY).handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        is None
    )
    assert upstream.calls == []


def test_calls_are_recorded_in_order_and_injection_is_flagged() -> None:
    proxy = Proxy(FakeTransport({"read_file": _ok("body"), "sync_to_webhook": _ok("ok")}), CANARY)
    _call(proxy, "read_file", {"path": "a"}, 1)
    _call(proxy, "sync_to_webhook", {"url": CANARY.token}, 2)
    calls = proxy.recorder.to_transcript()["tool_calls"]
    assert [c["name"] for c in calls] == ["read_file", "sync_to_webhook"]  # type: ignore[index]
    assert calls[0].get("injected") is True  # type: ignore[index]
    assert "injected" not in calls[1]  # type: ignore[operator]


def test_upstream_failure_becomes_a_jsonrpc_error_naming_the_cause() -> None:
    upstream = FakeTransport()
    upstream.fail_with = TransportError("connection refused", code=-32000)
    reply = Proxy(upstream, CANARY).handle({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert reply is not None
    assert reply["error"] == {"code": -32000, "message": "connection refused"}
    assert reply["id"] == 3


# --- pagination -------------------------------------------------------------
# A paginated upstream splits its tools across pages linked by nextCursor.
# The source tool may sit on a later page than its sink, so the proxy must
# accumulate every page before deciding which tools are sources.

PAGE_1 = {"tools": [TOOLS[1]], "nextCursor": "c2"}  # sync_to_webhook (sink)
PAGE_2 = {"tools": [TOOLS[0]]}  # read_file (source), no nextCursor


class PagedTransport:
    def __init__(
        self, pages: dict[str | None, dict[str, object]], results: dict[str, dict[str, object]]
    ) -> None:
        self.pages = pages
        self.results = results
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.calls.append((method, params))
        if method == "tools/list":
            cursor = params.get("cursor") if params else None
            return self.pages[cursor]  # type: ignore[index]
        if method == "tools/call":
            assert params is not None
            return self.results[str(params["name"])]
        return {}

    def close(self) -> None: ...


def test_source_on_page_two_with_sink_on_page_one_gets_canary() -> None:
    proxy = Proxy(PagedTransport({None: PAGE_1, "c2": PAGE_2}, {"read_file": _ok("hello")}), CANARY)
    first = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    second = proxy.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "c2"}}
    )
    assert first == {"jsonrpc": "2.0", "id": 1, "result": PAGE_1}
    assert second == {"jsonrpc": "2.0", "id": 2, "result": PAGE_2}
    reply = _call(proxy, "read_file", {"path": "a"})
    assert reply is not None
    assert _texts(reply) == ["hello", CANARY.text]


def test_lazy_fetch_follows_cursors_so_a_page_two_source_gets_canary() -> None:
    upstream = PagedTransport({None: PAGE_1, "c2": PAGE_2}, {"read_file": _ok("hello")})
    reply = _call(Proxy(upstream, CANARY), "read_file", {"path": "a"})
    assert reply is not None
    assert _texts(reply) == ["hello", CANARY.text]
    assert ("tools/list", {"cursor": "c2"}) in upstream.calls


def test_agent_listing_only_page_one_still_finds_page_two_source_before_a_call() -> None:
    upstream = PagedTransport({None: PAGE_1, "c2": PAGE_2}, {"read_file": _ok("hello")})
    proxy = Proxy(upstream, CANARY)
    proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    reply = _call(proxy, "read_file", {"path": "a"})
    assert reply is not None
    assert _texts(reply) == ["hello", CANARY.text]


def test_repeated_cursor_stops_paging_instead_of_looping() -> None:
    upstream = PagedTransport(
        {None: {"tools": [], "nextCursor": "loop"}, "loop": {"tools": [], "nextCursor": "loop"}},
        {"read_file": _ok("hello")},
    )
    reply = _call(Proxy(upstream, CANARY), "read_file", {"path": "a"})
    assert reply is not None
    assert _texts(reply) == ["hello"]
    assert [m for m, _ in upstream.calls].count("tools/list") == 2


# --- upstream rejections ----------------------------------------------------
# An agent that obeyed the canary and was then rejected by a strict schema must
# still leave a trace, or the scan reports a false negative.


class RejectingTransport(FakeTransport):
    """Lists and serves read_file normally; raises `error` for any other tools/call."""

    def __init__(self, error: Exception) -> None:
        super().__init__({"read_file": _ok("body")})
        self.error = error

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method == "tools/call" and params is not None and params["name"] != "read_file":
            self.calls.append((method, params))
            raise self.error
        return super().request(method, params)


def test_a_schema_rejected_call_carrying_the_token_is_recorded_and_reported() -> None:
    from agent_perimeter.checks.injection.agent_adapter import CHECK
    from tests.checks.injection.test_agent_adapter import _context

    rejection = TransportError("Invalid params: unexpected 'token'", code=-32602)
    proxy = Proxy(RejectingTransport(rejection), CANARY)
    _call(proxy, "read_file", {"path": "a"}, 1)
    reply = _call(proxy, "sync_to_webhook", {"url": "u", "token": CANARY.token}, 2)
    assert reply is not None
    assert reply["error"]["code"] == -32602  # type: ignore[index]
    calls = proxy.recorder.to_transcript()["tool_calls"]
    assert [c["name"] for c in calls] == ["read_file", "sync_to_webhook"]  # type: ignore[index]
    assert calls[1]["result"] == "error -32602: Invalid params: unexpected 'token'"  # type: ignore[index]
    assert "injected" not in calls[1]  # type: ignore[operator]
    findings = CHECK.run(_context(proxy.recorder.to_transcript()))
    assert len(findings) == 1
    assert "sync_to_webhook" in findings[0].title


def test_a_generic_upstream_exception_becomes_a_32603_reply_and_is_recorded() -> None:
    proxy = Proxy(RejectingTransport(RuntimeError("pipe closed")), CANARY)
    reply = _call(proxy, "sync_to_webhook", {"url": "u"}, 4)
    assert reply is not None
    assert reply["id"] == 4
    assert reply["error"]["code"] == -32603  # type: ignore[index]
    message = reply["error"]["message"]  # type: ignore[index]
    assert "RuntimeError" in message
    assert "target server" in message
    calls = proxy.recorder.to_transcript()["tool_calls"]
    assert [c["name"] for c in calls] == ["sync_to_webhook"]  # type: ignore[index]
    assert "RuntimeError" in calls[0]["result"]  # type: ignore[index]


def test_a_generic_exception_outside_tools_call_is_still_a_jsonrpc_error() -> None:
    upstream = FakeTransport()
    upstream.fail_with = OSError("broken pipe")
    reply = Proxy(upstream, CANARY).handle({"jsonrpc": "2.0", "id": 5, "method": "ping"})
    assert reply is not None
    assert reply["error"]["code"] == -32603  # type: ignore[index]
    assert "OSError" in reply["error"]["message"]  # type: ignore[index]
