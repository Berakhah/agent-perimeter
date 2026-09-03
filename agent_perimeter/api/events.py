# agent_perimeter/api/events.py
"""Per-scan progress events, kept in-process.

ponytail: single-process, in-memory only — a worker restart loses in-flight
and completed event history, and a multi-worker deployment would only show a
client the events recorded by whichever worker actually ran its scan. Move
to a durable/shared store (Postgres LISTEN/NOTIFY, Redis pub/sub) if this
needs to survive a restart or scale past one process. Same ceiling as the
findings/graph cache in api/state.py, for the same reason: Task 9 has no
queue/broker infrastructure anywhere in this repo to reach for.
"""

from __future__ import annotations

import threading
from dataclasses import asdict
from typing import Any

from agent_perimeter.checks.registry import Skipped
from agent_perimeter.scan_runner import EventFrame


class EventLog:
    """Append-only per-scan-id event log.

    One instance lives on `AppState.events`, written by the background task
    that runs the scan and read by the SSE endpoint (and the status
    endpoint, for "has this scan finished?").
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._frames: dict[str, list[dict[str, Any]]] = {}
        self._done: dict[str, bool] = {}

    def start(self, scan_id: str) -> None:
        """Registers `scan_id` as known, before the background task that
        will populate it has necessarily even started — so a client that
        polls immediately after POST sees "running", not "not found"."""
        with self._lock:
            self._frames.setdefault(scan_id, [])
            self._done[scan_id] = False

    def append(self, scan_id: str, frame: EventFrame) -> None:
        with self._lock:
            self._frames.setdefault(scan_id, []).append(asdict(frame))

    def finish(self, scan_id: str, *, skipped: list[Skipped], completed: int, total: int) -> None:
        """The terminal frame. Skipped checks are in the stream, not
        omitted — spec §7.3: a skipped check is never silently absent from
        the count, and the live screen is where that rule is most tempting
        to break."""
        with self._lock:
            self._frames.setdefault(scan_id, []).append(
                {
                    "terminal": True,
                    "completed": completed,
                    "total": total,
                    "skipped": [
                        {"check_id": s.check_id, "reason": s.reason.value, "detail": s.detail}
                        for s in skipped
                    ],
                }
            )
            self._done[scan_id] = True

    def frames(self, scan_id: str) -> list[dict[str, Any]] | None:
        """`None` means `scan_id` was never registered via `start()` — the
        caller's cue to answer 404, not an empty stream."""
        with self._lock:
            frames = self._frames.get(scan_id)
            return list(frames) if frames is not None else None

    def is_done(self, scan_id: str) -> bool:
        with self._lock:
            return self._done.get(scan_id, False)
