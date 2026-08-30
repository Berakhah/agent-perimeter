# agent_perimeter/db/models.py
"""Persistence for scans and findings. Mirrors spec section 5.

secret_finding carries a database CHECK constraint forbidding validated=true,
so hard constraint 3 — never validate a discovered secret against a live
service — is a schema invariant rather than a coding habit. There is also no
column anywhere that could hold a raw secret value, which a test asserts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_ref: Mapped[str] = mapped_column(Text)
    scope_file_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revision_claimed: Mapped[str | None] = mapped_column(String(16), nullable=True)
    revision_observed: Mapped[str | None] = mapped_column(String(16), nullable=True)
    feature_set_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mode: Mapped[str] = mapped_column(String(16))
    tool_version: Mapped[str] = mapped_column(String(32))


class ServerProfile(Base):
    __tablename__ = "server_profile"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    transport: Mapped[str] = mapped_column(String(32))
    auth_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tls_detail: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    capabilities_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    extensions_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)


class Tool(Base):
    __tablename__ = "tool"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    name: Mapped[str] = mapped_column(Text)
    description_hash: Mapped[str] = mapped_column(String(64))
    input_schema_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    annotations_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CapabilityEdge(Base):
    __tablename__ = "capability_edge"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tool_id: Mapped[str] = mapped_column(ForeignKey("tool.id"))
    capability: Mapped[str] = mapped_column(String(32))
    derived_from: Mapped[str] = mapped_column(String(16))
    claim_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)

    __table_args__ = (
        CheckConstraint(
            "derived_from IN ('schema', 'description', 'probe', 'artifact')",
            name="ck_capability_edge_derived_from",
        ),
    )


class FindingRow(Base):
    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    check_id: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    calibration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    cwe: Mapped[str] = mapped_column(String(16))
    taxonomy_refs_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    feature_requirements_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    title: Mapped[str] = mapped_column(Text)
    reproduction: Mapped[str] = mapped_column(Text)
    claim_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("finding.id"))
    kind: Mapped[str] = mapped_column(String(16))
    blob_ref: Mapped[str] = mapped_column(Text)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)


class SecretFinding(Base):
    __tablename__ = "secret_finding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan.id"))
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    entropy: Mapped[float] = mapped_column(Float)
    prefix: Mapped[str] = mapped_column(String(16))
    last4: Mapped[str] = mapped_column(String(4))
    location: Mapped[str] = mapped_column(Text)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        CheckConstraint("validated = false", name="ck_secret_finding_never_validated"),
    )


class DriftEvent(Base):
    __tablename__ = "drift_event"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tool_id: Mapped[str] = mapped_column(ForeignKey("tool.id"))
    field: Mapped[str] = mapped_column(String(32))
    old_hash: Mapped[str] = mapped_column(String(64))
    new_hash: Mapped[str] = mapped_column(String(64))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    severity: Mapped[str] = mapped_column(String(16))
