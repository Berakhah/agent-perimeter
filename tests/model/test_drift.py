"""Drift event model tests."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_perimeter._contracts import Severity
from agent_perimeter.model.drift import DRIFT_SEVERITY, DriftEvent, DriftField


def test_every_field_has_a_severity() -> None:
    assert set(DRIFT_SEVERITY) == set(DriftField)


def test_severity_mapping_is_the_one_the_spec_fixes() -> None:
    assert DRIFT_SEVERITY[DriftField.DESCRIPTION] is Severity.HIGH
    assert DRIFT_SEVERITY[DriftField.TOOL_ADDED] is Severity.HIGH
    assert DRIFT_SEVERITY[DriftField.INPUT_SCHEMA] is Severity.MEDIUM
    assert DRIFT_SEVERITY[DriftField.ANNOTATIONS] is Severity.MEDIUM
    assert DRIFT_SEVERITY[DriftField.TOOL_REMOVED] is Severity.LOW


def test_event_allows_a_missing_side_for_added_and_removed() -> None:
    event = DriftEvent(
        tool_name="x",
        field=DriftField.TOOL_ADDED,
        old_hash=None,
        new_hash="ab",
        old_value=None,
        new_value="new",
        severity=Severity.HIGH,
        detected_at=datetime(2026, 9, 15, tzinfo=UTC),
    )
    assert event.old_hash is None
