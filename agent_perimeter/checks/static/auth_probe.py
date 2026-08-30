"""An ordinary unauthenticated request, to observe the target's own 401 challenge.

Same category as Task 12's fetch_oauth_metadata: a plain request any client
would make, not a crafted payload, so it needs no scope file. Wired into
context.raw["_auth_probe"] by the CLI (Task 25) alongside the OAuth metadata
fetch, before checks run.
"""

from __future__ import annotations

import httpx


def probe_auth_challenge(target: str, *, client: httpx.Client | None = None) -> dict[str, object]:
    if not target.startswith(("http://", "https://")):
        return {}

    owned = client is None
    http = client or httpx.Client(timeout=10.0)
    try:
        response = http.post(target, json={"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
    except httpx.HTTPError:
        return {}
    finally:
        if owned:
            http.close()

    return {
        "status_code": response.status_code,
        "www_authenticate": response.headers.get("WWW-Authenticate", ""),
    }
