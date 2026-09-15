"""One detected change between two snapshots of the same target (spec §4.2)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from agent_perimeter._contracts import Severity


class DriftField(StrEnum):
    DESCRIPTION = "description"
    INPUT_SCHEMA = "input_schema"
    ANNOTATIONS = "annotations"
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"


# Fixed by the spec, not configurable: a changed description or a new tool
# is the rug-pull shape itself; a schema/annotation change is the quieter
# variant; a removed tool cannot instruct anything.
DRIFT_SEVERITY: dict[DriftField, Severity] = {
    DriftField.DESCRIPTION: Severity.HIGH,
    DriftField.TOOL_ADDED: Severity.HIGH,
    DriftField.INPUT_SCHEMA: Severity.MEDIUM,
    DriftField.ANNOTATIONS: Severity.MEDIUM,
    DriftField.TOOL_REMOVED: Severity.LOW,
}


class DriftEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_name: str
    field: DriftField
    old_hash: str | None
    new_hash: str | None
    old_value: str | None
    new_value: str | None
    severity: Severity
    detected_at: datetime
