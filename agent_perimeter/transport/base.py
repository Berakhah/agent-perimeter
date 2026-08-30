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
