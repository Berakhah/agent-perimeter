# agent_perimeter/api/schemas.py
"""Request bodies for the API.

Response payloads are the existing domain models (Finding, CapabilityEdge,
the SARIF dict) encoded with `fastapi.encoders.jsonable_encoder` directly in
scans.py/census.py — no shadow response schema to keep in sync with them.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict

from agent_perimeter.scan_runner import ScanMode


class ScopeFileInput(BaseModel):
    """Everything `ScopeFile` needs, from an HTTP request body.

    Every field is optional here — unlike `ScopeFile` itself — so FastAPI's
    own request parsing never raises a generic 422 before this API's own
    refusal (structured the same way `AuthorizationRequired` is) gets a
    chance to name the *specific* missing field. `authorised_on` additionally
    defaults to today when the real `ScopeFile` is built: a scan authorised
    with no explicit start date is read as starting now, a deliberate
    default, not an oversight (Task 9 ruling #7).
    """

    model_config = ConfigDict(extra="forbid")

    target: str | None = None
    authorising_party: str | None = None
    authorised_on: date | None = None
    attestation: str | None = None
    expires_on: date | None = None


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    mode: ScanMode = ScanMode.PASSIVE
    scope_file: ScopeFileInput | None = None
