import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_perimeter import cli
from agent_perimeter.instrument import server
from tests.instrument.test_proxy import FakeTransport

runner = CliRunner()
TARGET = "https://mcp.example.test/rpc"


def _scope(path: Path, *, target: str = TARGET, expires: str | None = None) -> Path:
    body: dict[str, str] = {
        "target": target,
        "authorising_party": "Example Corp security",
        "authorised_on": date.today().isoformat(),
        "attestation": "We own this server and authorise instrumented testing.",
    }
    if expires:
        body["expires_on"] = expires
    path.write_text(json.dumps(body))
    return path


@pytest.fixture
def no_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("a transport was opened before authorisation was checked")

    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", _boom)
    monkeypatch.setattr(server, "serve", _boom)


def test_refuses_without_a_scope_file_before_opening_anything(no_transport: None) -> None:
    result = runner.invoke(cli.app, ["instrument", "--target", TARGET])
    assert result.exit_code == 2
    assert "no scope file was supplied" in result.output


def test_refuses_a_scope_for_a_different_target(no_transport: None, tmp_path: Path) -> None:
    scope = _scope(tmp_path / "s.json", target="https://other.example.test/rpc")
    result = runner.invoke(cli.app, ["instrument", "--target", TARGET, "--scope-file", str(scope)])
    assert result.exit_code == 2
    assert "scope file target is" in result.output


def test_refuses_an_expired_scope(no_transport: None, tmp_path: Path) -> None:
    scope = _scope(tmp_path / "s.json", expires="2000-01-01")
    # authorised_on is today, so an expiry in 2000 is rejected by ScopeFile itself.
    result = runner.invoke(cli.app, ["instrument", "--target", TARGET, "--scope-file", str(scope)])
    assert result.exit_code == 2


def test_authorised_run_serves_on_loopback_and_writes_the_transcript(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeTransport()
    seen: dict[str, object] = {}
    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", lambda *_a, **_k: fake)

    def _serve(proxy: object, *, port: int, host: str = server.LOOPBACK_HOST) -> None:
        seen.update(port=port, host=host)

    monkeypatch.setattr(server, "serve", _serve)
    out = tmp_path / "t.json"
    scope = _scope(tmp_path / "s.json")
    result = runner.invoke(
        cli.app,
        [
            "instrument",
            "--target",
            TARGET,
            "--scope-file",
            str(scope),
            "--port",
            "9123",
            "--transcript-out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == {"port": 9123, "host": "127.0.0.1"}
    assert json.loads(out.read_text())["tool_calls"] == []


def test_busy_port_gets_the_port_message_and_exit_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import socket

    fake = FakeTransport()
    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", lambda *_a, **_k: fake)
    scope = _scope(tmp_path / "s.json")
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        result = runner.invoke(
            cli.app,
            [
                "instrument",
                "--target",
                TARGET,
                "--scope-file",
                str(scope),
                "--port",
                str(port),
                "--transcript-out",
                str(tmp_path / "t.json"),
            ],
        )
    assert result.exit_code == 2, result.output
    assert str(port) in result.output
    assert "--port" in result.output
    assert fake.closed


def test_unwritable_transcript_still_closes_the_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeTransport()
    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", lambda *_a, **_k: fake)
    monkeypatch.setattr(server, "serve", lambda *_a, **_k: None)
    scope = _scope(tmp_path / "s.json")
    result = runner.invoke(
        cli.app,
        [
            "instrument",
            "--target",
            TARGET,
            "--scope-file",
            str(scope),
            "--transcript-out",
            str(tmp_path / "missing-dir" / "t.json"),
        ],
    )
    assert fake.closed
    assert "Could not write transcript" in result.output
