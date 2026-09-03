# agent_perimeter/api/state.py
"""Per-app-instance shared, in-process state.

One instance is built in `app.create_app()` and stored on `app.state.ap`,
read by every route in scans.py/census.py. Kept in its own module (not
app.py) only to avoid an app.py <-> scans.py/census.py import cycle: app.py
builds this and mounts the routers; the routers only need this shape, not
app.py itself.

ponytail: `results`/`requests` below are the in-process cache Task 9 ruling
#5 accepts as a known gap — `findings`/`graph`/`report.sarif` serve from it
because `FindingRow`/`CapabilityEdge` (the DB rows) cannot losslessly
reconstruct a `Finding.evidence`/`Finding.location` or a `CapabilityEdge`
without a schema change outside this task's scope. A worker restart loses
every in-flight or completed scan's cached result; the DB rows written
alongside (Scan/Tool/CapabilityEdge/FindingRow, best-effort — see scans.py)
exist for durability/audit, not as this cache's fallback. Move to a shared
store if that ever needs to survive a restart.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from sqlalchemy.orm import Session, sessionmaker

from agent_perimeter.api.events import EventLog
from agent_perimeter.api.schemas import ScanRequest
from agent_perimeter.scan_runner import ScanOutcome


@dataclass
class AppState:
    session_factory: sessionmaker[Session]
    events: EventLog = field(default_factory=EventLog)
    results: dict[str, ScanOutcome] = field(default_factory=dict)
    """`None`-valued entries are never stored — a missing key means "not
    finished yet or errored", disambiguated via `events.is_done`."""
    requests: dict[str, ScanRequest] = field(default_factory=dict)
    """The original request, kept so /report.sarif can pass the real
    `target` to `to_sarif()` without threading it through `ScanOutcome`."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    """Guards `results`/`requests` — the background task writes them from a
    different thread than the one FastAPI's threadpool answers a GET on."""
