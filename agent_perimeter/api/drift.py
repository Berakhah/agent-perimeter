# agent_perimeter/api/drift.py
"""Baseline loading and the drift read route.

This is the first route that reads from the database. Task 9's ruling ("DB
is durability/audit only, never the read path") stands for findings, graph
and SARIF; drift is *history*, and the in-process cache cannot hold history
across restarts (spec §7.4).
"""

from __future__ import annotations

import logging
from typing import NamedTuple

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from agent_perimeter.api.state import AppState
from agent_perimeter.db.models import DriftEvent as DriftEventRow
from agent_perimeter.db.models import Scan, Tool
from agent_perimeter.drift.compare import positional_keys
from agent_perimeter.model.snapshot import SnapshotTool, ToolSnapshot, canonical_json, sha256_json

logger = logging.getLogger(__name__)
router = APIRouter()

TIMELINE_LIMIT = 20


class BaselineLookup(NamedTuple):
    snapshot: ToolSnapshot | None
    source_unavailable: bool


def snapshot_from_scan(session: Session, scan: Scan) -> ToolSnapshot:
    rows = (
        session.execute(select(Tool).where(Tool.scan_id == scan.id).order_by(Tool.position))
        .scalars()
        .all()
    )
    tools = [
        SnapshotTool(
            name=row.name,
            # Pre-0006 rows have no text; the stored hash still compares.
            description=row.description or "",
            input_schema=row.input_schema_json,
            annotations=row.annotations_json,
            description_hash=row.description_hash,
            schema_hash=sha256_json(row.input_schema_json),
            annotations_hash=sha256_json(row.annotations_json),
        )
        for row in rows
    ]
    return ToolSnapshot(
        target=scan.target_ref,
        taken_at=scan.finished_at or scan.started_at,
        scan_id=scan.id,
        tools=tools,
    )


def _mismatch(message: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"error": "baseline_mismatch", "message": message})


def load_baseline(
    session_factory: sessionmaker[Session], target_ref: str, *, pinned: str | None
) -> BaselineLookup:
    try:
        with session_factory() as session:
            if pinned is not None:
                scan = session.get(Scan, pinned)
                if scan is None or scan.finished_at is None:
                    raise _mismatch(
                        f"baseline_scan_id {pinned!r} is not a finished scan on record. "
                        "Pass the id of a completed scan of this target, or omit it."
                    )
                if scan.target_ref != target_ref:
                    raise _mismatch(
                        f"baseline_scan_id {pinned!r} scanned {scan.target_ref!r}, not "
                        f"{target_ref!r}. Drift is only meaningful for one target."
                    )
                return BaselineLookup(snapshot_from_scan(session, scan), False)
            scan = session.execute(
                select(Scan)
                .where(Scan.target_ref == target_ref, Scan.finished_at.is_not(None))
                .order_by(Scan.finished_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if scan is None:
                return BaselineLookup(None, False)
            return BaselineLookup(snapshot_from_scan(session, scan), False)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 - best-effort like _persist; the cause is named in the skip
        logger.info("no baseline for %s: database unreachable", target_ref, exc_info=True)
        return BaselineLookup(None, True)


def _text(field: str, tool: Tool | None) -> str | None:
    if tool is None:
        return None
    if field == "input_schema":
        return canonical_json(tool.input_schema_json)
    if field == "annotations":
        return canonical_json(tool.annotations_json)
    return tool.description


def _drifted_tool(
    event: DriftEventRow,
    current_by_id: dict[str, Tool],
    current_key_by_id: dict[str, str],
    baseline_by_id: dict[str, Tool],
    baseline_by_key: dict[str, Tool],
) -> dict[str, object]:
    tool = current_by_id.get(event.tool_id)
    if tool is not None:
        # Non-removed events: event.tool_id names a row in the *current*
        # scan. Look up its counterpart on the baseline side by the same
        # positional key (spec §5.1) -- not by name, which collapses
        # duplicates the way `event.tool_id` itself does not.
        key = current_key_by_id[tool.id]
        name = tool.name
        before = baseline_by_key.get(key)
        after = tool
    else:
        # tool_removed: event.tool_id names a row in the *baseline* scan
        # directly (it has no counterpart in the current scan at all), so
        # no positional-key lookup is needed to find it -- the FK already
        # points at the exact copy that was removed.
        before = baseline_by_id.get(event.tool_id)
        name = before.name if before is not None else "?"
        after = None
    return {
        "name": name,
        "field": event.field,
        "severity": event.severity,
        "old_hash": event.old_hash,
        "new_hash": event.new_hash,
        "old_text": None if event.field == "tool_added" else _text(event.field, before),
        "new_text": _text(event.field, after),
    }


@router.get("/scans/{scan_id}/drift")
def get_drift(scan_id: str, request: Request) -> dict[str, object]:
    state: AppState = request.app.state.ap
    if state.events.frames(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not state.events.is_done(scan_id):
        raise HTTPException(status_code=409, detail="scan is still running")
    with state.session_factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        history = (
            session.execute(
                select(Scan)
                .where(Scan.target_ref == scan.target_ref, Scan.finished_at.is_not(None))
                .order_by(Scan.finished_at.desc(), Scan.started_at.desc())
                .limit(TIMELINE_LIMIT)
            )
            .scalars()
            .all()
        )
        count_rows = session.execute(
            select(Tool.scan_id, func.count(Tool.id))
            .where(Tool.scan_id.in_([s.id for s in history]))
            .group_by(Tool.scan_id)
        ).all()
        counts: dict[str, int] = {row[0]: row[1] for row in count_rows}
        events = (
            session.execute(
                select(DriftEventRow)
                .where(DriftEventRow.scan_id == scan_id)
                .order_by(DriftEventRow.tool_id, DriftEventRow.field)
            )
            .scalars()
            .all()
        )
        baseline_id = events[0].baseline_scan_id if events else None
        current_rows = (
            session.execute(select(Tool).where(Tool.scan_id == scan_id).order_by(Tool.position))
            .scalars()
            .all()
        )
        current_by_id = {t.id: t for t in current_rows}
        current_key_by_id = dict(
            zip(
                (t.id for t in current_rows),
                positional_keys(t.name for t in current_rows),
                strict=True,
            )
        )
        baseline_by_id: dict[str, Tool] = {}
        baseline_by_key: dict[str, Tool] = {}
        if baseline_id is not None:
            baseline_rows = (
                session.execute(
                    select(Tool).where(Tool.scan_id == baseline_id).order_by(Tool.position)
                )
                .scalars()
                .all()
            )
            baseline_by_id = {t.id: t for t in baseline_rows}
            baseline_keys = positional_keys(t.name for t in baseline_rows)
            baseline_by_key = dict(zip(baseline_keys, baseline_rows, strict=True))
        drifted = [
            _drifted_tool(e, current_by_id, current_key_by_id, baseline_by_id, baseline_by_key)
            for e in events
        ]
        timeline = [
            {
                "id": s.id,
                "started_at": s.started_at.isoformat(),
                "tool_count": int(counts.get(s.id, 0)),
            }
            for s in history
        ]
    return {
        "scan_id": scan_id,
        "target_ref": scan.target_ref,
        "baseline_scan_id": baseline_id,
        "scans": timeline,
        "drifted_tools": drifted,
    }
