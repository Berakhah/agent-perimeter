"""HTTP+SSE transport — deprecated, retained for legacy targets only.

Deprecated in protocol version 2025-03-26 and formally reclassified as
Deprecated by SEP-2596 in 2026-07-28. This is not a peer of Streamable HTTP;
it exists so the scanner and the census can still reach older servers, which
are most of the population one month after a breaking revision.
"""

from __future__ import annotations

import warnings

import httpx

from agent_perimeter.transport.base import TransportError

DEPRECATED_SINCE = "2025-03-26"
CLIENT_NAME = "agent-perimeter"
CLIENT_VERSION = "0.1.0"


class LegacySseTransport:
    def __init__(self, url: str, *, timeout_s: float = 30.0, contact_url: str) -> None:
        warnings.warn(
            f"HTTP+SSE has been deprecated since {DEPRECATED_SINCE} and is Deprecated "
            f"under the 2026-07-28 feature lifecycle policy. Use Streamable HTTP "
            f"unless the target predates it.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._url = url
        self._client = httpx.Client(timeout=timeout_s)
        self._contact_url = contact_url

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION} (+{self._contact_url})",
        }
        response = self._client.post(self._url, json=body, headers=headers)
        if response.status_code >= 400:
            msg = f"{self._url} returned {response.status_code} for {method}."
            raise TransportError(msg)

        try:
            message = response.json()
        except (ValueError, RecursionError) as exc:
            msg = f"{response.status_code} response body was not valid JSON"
            raise TransportError(msg) from exc
        if not isinstance(message, dict):
            msg = "Response body was not a JSON object"
            raise TransportError(msg)
        if "error" in message:
            msg = f"Server returned an error for {method}: {message['error']}"
            raise TransportError(msg)
        result = message.get("result", {})
        if not isinstance(result, dict):
            msg = f"Server returned a non-object result for {method}"
            raise TransportError(msg)
        return result

    def close(self) -> None:
        self._client.close()
