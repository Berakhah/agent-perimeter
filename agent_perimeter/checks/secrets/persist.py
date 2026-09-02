# agent_perimeter/checks/secrets/persist.py
"""Write a detected secret's fingerprint to the database.

Counterpart to purge.py's delete side: a SecretFingerprint carries only its
non-reversible fields (sha256, entropy, prefix, last4, location), so mapping
it onto a SecretFinding row cannot leak a raw value, and `validated` is never
set — hard constraint 3 stays true structurally, same as the DB's own
CHECK constraint.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from agent_perimeter._contracts import SecretFingerprint
from agent_perimeter.db.models import SecretFinding


def record_secret_finding(
    session: Session, *, scan_id: str, fingerprint: SecretFingerprint
) -> SecretFinding:
    row = SecretFinding(
        scan_id=scan_id,
        fingerprint_sha256=fingerprint.sha256,
        entropy=fingerprint.entropy,
        prefix=fingerprint.prefix,
        last4=fingerprint.last4,
        location=fingerprint.location,
    )
    session.add(row)
    session.commit()
    return row
