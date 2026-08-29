"""Authorisation for active probing. Fails closed, always.

Hard constraint 1: the tool refuses active probes without a scope file naming
the target, the authorising party and a date. Unauthorised probing is a
criminal-liability question in most jurisdictions, not a style preference.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator


class AuthorizationRequired(Exception):
    """Raised when an active check is attempted without valid authorisation."""


class ScopeFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str
    authorising_party: str
    authorised_on: date
    attestation: str
    expires_on: date | None = None

    @field_validator("target", "authorising_party", "attestation")
    @classmethod
    def _must_not_be_blank(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            msg = f"{info.field_name} must not be blank"
            raise ValueError(msg)
        return value


def require_scope(
    scope: ScopeFile | None,
    *,
    check_id: str,
    target: str,
    today: date,
) -> None:
    """Raise unless `scope` authorises active probing of `target` on `today`.

    The message names the specific missing or failing field, because an error
    that does not say what to do next is not an error message.
    """
    if scope is None:
        msg = (
            f"Check {check_id} is an active probe and no scope file was supplied. "
            f"Attach a scope file naming target, authorising_party, authorised_on "
            f"and attestation."
        )
        raise AuthorizationRequired(msg)

    if scope.target != target:
        msg = (
            f"Check {check_id} refused: scope file target is {scope.target!r} "
            f"but the scan target is {target!r}. Field: target."
        )
        raise AuthorizationRequired(msg)

    if scope.expires_on is not None and scope.expires_on < today:
        msg = (
            f"Check {check_id} refused: authorisation lapsed on {scope.expires_on}. "
            f"Field: expires_on."
        )
        raise AuthorizationRequired(msg)
