"""Loopback HTTP wrapper around Proxy.handle.

The proxy forwards an agent's tools/call to a real server, so it must never be
reachable from another machine: the bind address is fixed to loopback and
checked, not merely defaulted.
"""

from __future__ import annotations

import ipaddress
import socket

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from agent_perimeter.instrument.proxy import Proxy

LOOPBACK_HOST = "127.0.0.1"


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


def _bad_request() -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32700,
                "message": "Request body is not a JSON object. Send a JSON-RPC 2.0 request.",
            },
        },
        status_code=400,
    )


def create_app(proxy: Proxy) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/")
    async def rpc(request: Request) -> Response:
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
        probe.bind((host, port))
    uvicorn.run(create_app(proxy), host=host, port=port, log_level="warning")
