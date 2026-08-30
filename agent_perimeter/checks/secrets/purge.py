# agent_perimeter/checks/secrets/purge.py
"""Delete secret_finding rows past their retention window.

Closes B4: fingerprints have a retention limit and automatic deletion, not
just a schema field that nothing ever reads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, delete, or_
from sqlalchemy.orm import Session

from agent_perimeter.db.models import SecretFinding


def purge_expired_secrets(session: Session, *, now: datetime | None = None) -> int:
    cutoff = now or datetime.now(UTC)
    # A NULL expires_at (existing rows from before this column had a value —
    # the migration added it as nullable, with no backfill) is also eligible:
    # a fingerprint with no recorded expiry shouldn't accumulate indefinitely
    # either, consistent with B4's bounded-retention intent.
    result = session.execute(
        delete(SecretFinding).where(
            or_(SecretFinding.expires_at.is_(None), SecretFinding.expires_at < cutoff)
        )
    )
    session.commit()
    # session.execute() on a DELETE returns a CursorResult at runtime, but its
    # static return type is the generic Result[Any], which has no .rowcount.
    return cast(CursorResult[Any], result).rowcount
