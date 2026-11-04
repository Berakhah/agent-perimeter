import pytest
from fastapi.testclient import TestClient

from agent_perimeter.instrument.canary import Canary
from agent_perimeter.instrument.proxy import Proxy
from agent_perimeter.instrument.server import assert_loopback, create_app
from tests.instrument.test_proxy import FakeTransport

CANARY = Canary(nonce="00ff00ff00ff00ff")
PORT = 8931
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def _client(upstream: FakeTransport | None = None) -> TestClient:
    proxy = Proxy(upstream if upstream is not None else FakeTransport(), CANARY)
    return TestClient(create_app(proxy, port=PORT), base_url=f"http://127.0.0.1:{PORT}")


# --- browser-origin defences ------------------------------------------------
# Loopback binding does not stop a page in the user's own browser: a
# text/plain POST is a CORS simple request (no preflight), and DNS rebinding
# lets a foreign Host reach 127.0.0.1. Each must be refused before upstream.


def test_cross_origin_request_is_refused_before_reaching_upstream() -> None:
    upstream = FakeTransport()
    response = _client(upstream).post("/", json=PING, headers={"origin": "https://evil.example"})
    assert response.status_code == 403
    assert "Origin" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_foreign_host_header_is_refused_before_reaching_upstream() -> None:
    upstream = FakeTransport()
    response = _client(upstream).post("/", json=PING, headers={"host": "attacker.example:8931"})
    assert response.status_code == 403
    assert "Host" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_text_plain_simple_request_is_refused_before_reaching_upstream() -> None:
    upstream = FakeTransport()
    response = _client(upstream).post(
        "/",
        content=b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}}',
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 415
    assert "application/json" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_the_reported_csrf_reproduction_is_refused() -> None:
    upstream = FakeTransport()
    response = _client(upstream).post(
        "/",
        content=b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}',
        headers={
            "content-type": "text/plain",
            "origin": "https://evil.example",
            "host": "attacker.example:8931",
        },
    )
    assert response.status_code == 403
    assert upstream.calls == []


@pytest.mark.parametrize("origin", [f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"])
def test_same_origin_request_with_charset_is_allowed(origin: str) -> None:
    response = _client().post(
        "/",
        content=b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}',
        headers={"origin": origin, "content-type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 200
    assert response.json()["result"] == {"echo": "ping"}


def test_localhost_host_header_is_allowed() -> None:
    response = _client().post("/", json=PING, headers={"host": f"localhost:{PORT}"})
    assert response.status_code == 200


def test_origin_on_another_loopback_port_is_refused() -> None:
    response = _client().post("/", json=PING, headers={"origin": "http://127.0.0.1:9999"})
    assert response.status_code == 403


def test_post_round_trips_a_jsonrpc_request() -> None:
    response = _client().post("/", json=PING)
    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "id": 1, "result": {"echo": "ping"}}


def test_notification_gets_202_and_no_body() -> None:
    response = _client().post("/", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202
    assert response.content == b""


def test_non_json_body_is_a_400_that_says_what_to_send() -> None:
    response = _client().post(
        "/", content=b"not json", headers={"content-type": "application/json"}
    )
    assert response.status_code == 400
    assert "JSON-RPC 2.0" in response.json()["error"]["message"]


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "192.168.1.5", "example.com", "::"],  # noqa: S104 -- hosts that must be refused
)
def test_non_loopback_hosts_are_refused(host: str) -> None:
    with pytest.raises(ValueError, match="loopback"):
        assert_loopback(host)


def test_loopback_host_is_accepted() -> None:
    assert_loopback("127.0.0.1")


def test_serve_raises_oserror_on_a_busy_port() -> None:
    import socket

    from agent_perimeter.instrument.server import serve

    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        with pytest.raises(OSError):
            serve(Proxy(FakeTransport(), CANARY), port=busy.getsockname()[1])


class _ProbeSocket:
    instances: list["_ProbeSocket"] = []

    def __init__(self, *_a: object) -> None:
        self.options: list[tuple[int, int, int]] = []
        _ProbeSocket.instances.append(self)

    def __enter__(self) -> "_ProbeSocket":
        return self

    def __exit__(self, *_a: object) -> None: ...

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def bind(self, _address: object) -> None: ...


@pytest.mark.parametrize(("os_name", "expect_reuse"), [("posix", True), ("nt", False)])
def test_port_probe_sets_reuseaddr_on_posix_only(
    monkeypatch: pytest.MonkeyPatch, os_name: str, expect_reuse: bool
) -> None:
    # POSIX: a port in TIME_WAIT after Ctrl+C must not read as "busy".
    # Windows: SO_REUSEADDR would let the probe bind a port another process holds.
    import socket

    from agent_perimeter.instrument import server

    _ProbeSocket.instances = []
    monkeypatch.setattr(server.os, "name", os_name)
    monkeypatch.setattr(server.socket, "socket", _ProbeSocket)
    monkeypatch.setattr(server.uvicorn, "run", lambda *_a, **_k: None)
    server.serve(Proxy(FakeTransport(), CANARY), port=PORT)
    reuse = (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    assert (reuse in _ProbeSocket.instances[0].options) is expect_reuse


def test_serve_refuses_non_loopback_before_reaching_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_perimeter.instrument import server

    def _fail(*_a: object, **_k: object) -> None:
        raise AssertionError("uvicorn.run was reached with a non-loopback host")

    monkeypatch.setattr(server.uvicorn, "run", _fail)
    with pytest.raises(ValueError, match="loopback"):
        server.serve(
            Proxy(FakeTransport(), CANARY),
            port=0,
            host="0.0.0.0",  # noqa: S104 -- must be refused
        )
