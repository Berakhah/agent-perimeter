"""Loopback HTTP wrapper around Proxy.handle.

The proxy forwards an agent's tools/call to a real server, so it must never be
reachable from another machine: the bind address is fixed to loopback and
checked, not merely defaulted.

Loopback alone does not stop a page in the user's own browser. A text/plain
POST is a CORS simple request (no preflight), and DNS rebinding points a
foreign hostname at 127.0.0.1. So every request must carry a loopback Host for
this port, any Origin must be this proxy's own, and the body must be declared
application/json (which a cross-origin page cannot send without a preflight).
"""

from __future__ import annotations

import ipaddress
import os
import socket

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from agent_perimeter.instrument.proxy import Proxy

LOOPBACK_HOST = "127.0.0.1"
_LOOPBACK_NAMES = ("127.0.0.1", "localhost")


def assert_loopback(host: str) -> None:
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        msg = (
            f"Refused to bind {host!r}: the instrument proxy forwards tool calls to a "
            f"real server and must stay on loopback. Use {LOOPBACK_HOST}."
        )
        raise ValueError(msg)


def _rpc_error(code: int, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}},
        status_code=status_code,
    )


def _bad_request() -> JSONResponse:
    return _rpc_error(
        -32700, "Request body is not a JSON object. Send a JSON-RPC 2.0 request.", 400
    )


def _refusal(request: Request, port: int) -> JSONResponse | None:
    """The reason to refuse this request before it reaches the upstream, if any."""
    allowed_hosts = {f"{name}:{port}" for name in _LOOPBACK_NAMES}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}
    origin = request.headers.get("origin")
    if origin is not None and origin.lower() not in allowed_origins:
        return _rpc_error(
            -32600,
            f"Refused a request with Origin {origin!r}: the instrument proxy only accepts "
            f"requests from your agent, not from a web page. Send it without an Origin "
            f"header, or from http://{LOOPBACK_HOST}:{port}.",
            403,
        )
    host = request.headers.get("host", "")
    if host.lower() not in allowed_hosts:
        return _rpc_error(
            -32600,
            f"Refused a request with Host {host!r}: the instrument proxy only answers "
            f"http://{LOOPBACK_HOST}:{port} or http://localhost:{port}. Point your agent "
            f"at one of those.",
            403,
        )
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        return _rpc_error(
            -32600,
            f"Refused a request with content type {media_type or 'none'!r}. Send the "
            f"JSON-RPC request with Content-Type: application/json.",
            415,
        )
    return None


def create_app(proxy: Proxy, *, port: int) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/")
    async def rpc(request: Request) -> Response:
        refusal = _refusal(request, port)
        if refusal is not None:
            return refusal
        try:
            message = await request.json()
        except ValueError:
            return _bad_request()
        if not isinstance(message, dict):
            return _bad_request()
        reply = await run_in_threadpool(proxy.handle, message)
        if reply is None:
            return Response(status_code=202)
        return JSONResponse(reply)

    return app


def serve(proxy: Proxy, *, port: int, host: str = LOOPBACK_HOST) -> None:
    assert_loopback(host)
    # uvicorn swallows a bind failure into sys.exit(3); probe first so the
    # caller gets a real OSError it can turn into an actionable message.
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        if os.name != "nt":
            # POSIX: a port left in TIME_WAIT by the last Ctrl+C is free, not busy.
            # Not on Windows, where SO_REUSEADDR would let us bind a port in use.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
    uvicorn.run(create_app(proxy, port=port), host=host, port=port, log_level="warning")
