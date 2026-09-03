"""Census domain types. Nothing here talks to a third-party MCP server."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Ecosystem(StrEnum):
    PYPI = "pypi"
    NPM = "npm"


class FetchStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    THROTTLED = "throttled"
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"
    UNSUPPORTED_COORDS = "unsupported_coords"
    TOO_LARGE = "too_large"

    @property
    def is_failure(self) -> bool:
        return self is not FetchStatus.OK


class PackageCoords(BaseModel):
    model_config = ConfigDict(frozen=True)

    ecosystem: Ecosystem
    name: str
    version: str | None = None

    def digest(self, salt: bytes) -> str:
        """Stable pseudonym. Published raw data is keyed by this, never by name.

        The salt is withheld for the embargo period (docs/security.md), which is
        what lets per-record measurements ship on day one without naming anyone.
        """
        payload = f"{self.ecosystem.value}:{self.name.lower()}".encode()
        return hashlib.blake2b(payload, key=salt, digest_size=16).hexdigest()
