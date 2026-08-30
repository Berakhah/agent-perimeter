from __future__ import annotations

from typing import Protocol


class TransportError(Exception):
    """The transport could not complete a request.

    `code` carries the JSON-RPC error code when one was observed (e.g. from
    a `server/discover` failure) — 2026-07-28 allocates specific codes as a
    deterministic revision fingerprint (Task 8), so it travels with the
    exception rather than being lost in a formatted message string.
    """

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class Transport(Protocol):
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        """Send one JSON-RPC request and return its result object."""
        ...

    def close(self) -> None: ...


#: `revision.header_body_mismatch` asks a transport to send a request whose
#: routing header disagrees with its body. Only Streamable HTTP has a header
#: to diverge from — `StreamableHttpTransport.request()` pops this param and
#: builds the mismatched request. Any other transport would forward it as an
#: ordinary JSON-RPC param, which a tolerant server ignores while answering
#: normally; the check reads "no error" as "the body was honoured" and emits
#: a HIGH-severity false positive. So the boundary is explicit rather than
#: silently degrading: a transport that cannot honour it says so.
HEADER_OVERRIDE_PARAM = "_ap_header_override"


def _reject_header_override(transport: object, params: dict[str, object] | None) -> None:
    """Fail closed on a probe param this transport cannot actually perform."""
    if params and HEADER_OVERRIDE_PARAM in params:
        msg = f"{type(transport).__name__} does not support header/body divergence probing"
        raise TransportError(msg)
