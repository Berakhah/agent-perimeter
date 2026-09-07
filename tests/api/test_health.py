"""GET /api/health — the compose healthcheck and scripts/smoke.sh's first
assertion both target this route (task 17 ruling 3: it did not exist before
this task). No database, no scan pipeline; a plain liveness probe.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from agent_perimeter.api.app import create_app

client = TestClient(create_app())


def test_health_reports_ok() -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
