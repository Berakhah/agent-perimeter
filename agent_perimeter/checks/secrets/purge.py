# agent_perimeter/checks/secrets/purge.py
"""Delete secret_finding rows past their retention window.

Closes B4: fingerprints have a retention limit and automatic deletion, not
just a schema field that nothing ever reads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.orm import Session

from agent_perimeter.db.models import SecretFinding


def purge_expired_secrets(session: Session, *, now: datetime | None = None) -> int:
    cutoff = now or datetime.now(UTC)
    result = session.execute(delete(SecretFinding).where(SecretFinding.expires_at < cutoff))
    session.commit()
    # session.execute() on a DELETE returns a CursorResult at runtime, but its
    # static return type is the generic Result[Any], which has no .rowcount.
    return cast(CursorResult[Any], result).rowcount
