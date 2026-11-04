import pytest
from fastapi.testclient import TestClient

from agent_perimeter.instrument.canary import Canary
from agent_perimeter.instrument.proxy import Proxy
from agent_perimeter.instrument.server import assert_loopback, create_app
from tests.instrument.test_proxy import FakeTransport

CANARY = Canary(nonce="00ff00ff00ff00ff")


def _client() -> TestClient:
    return TestClient(create_app(Proxy(FakeTransport(), CANARY)))


def test_post_round_trips_a_jsonrpc_request() -> None:
    response = _client().post("/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
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
