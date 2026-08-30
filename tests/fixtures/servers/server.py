"""A parameterised MCP fixture server.

AP_FIXTURE_REVISION selects the protocol revision it speaks.
AP_FIXTURE_FLAW injects exactly one flaw. Contains no secrets.
"""

import json
import os
import sys

REVISION = os.environ.get("AP_FIXTURE_REVISION", "2026-07-28")
FLAW = os.environ.get("AP_FIXTURE_FLAW", "none")


def _tools() -> list[dict]:
    return [
        {
            "name": "read_file",
            "description": "Read a file from the local workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]


def _tools_list_result() -> dict:
    result: dict = {"tools": _tools()}
    if REVISION != "2026-07-28":
        return result

    result["resultType"] = "complete"
    result["ttlMs"] = 60000
    result["cacheScope"] = "public" if FLAW == "cache_scope_public" else "private"

    if FLAW == "missing_result_type":
        del result["resultType"]
    if FLAW == "param_header":
        result["tools"][0]["inputSchema"]["properties"]["x-mcp-header"] = {"type": "string"}
    return result


def _discover_result() -> dict:
    return {
        "resultType": "complete",
        "protocolVersions": ["2026-07-28"],
        "capabilities": {"tools": {}, "extensions": {}},
        "serverInfo": {"name": "ap-fixture", "version": "0.1.0"},
    }


def _not_found(request_id: object) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def handle(message: dict) -> dict:
    method = message.get("method")
    request_id = message.get("id")

    if method == "server/discover":
        if REVISION != "2026-07-28":
            return _not_found(request_id)
        return {"jsonrpc": "2.0", "id": request_id, "result": _discover_result()}

    if method == "initialize":
        if REVISION == "2026-07-28":
            return _not_found(request_id)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": REVISION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ap-fixture", "version": "0.1.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": _tools_list_result()}

    return _not_found(request_id)


def main() -> None:
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle(json.loads(line))), flush=True)


if __name__ == "__main__":
    main()
