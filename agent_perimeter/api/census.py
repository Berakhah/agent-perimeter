# agent_perimeter/api/census.py
"""GET /api/census/runs/{id} -- read-only status for a `agent-perimeter
census` run. The census pipeline itself (Tasks 1-8) has no HTTP trigger; this
only reads what a run already wrote to the database.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from agent_perimeter.api.state import AppState
from agent_perimeter.db.models import CensusRun

router = APIRouter()


@router.get("/census/runs/{run_id}")
def get_census_run(run_id: int, request: Request) -> dict[str, object]:
    state: AppState = request.app.state.ap
    with state.session_factory() as session:
        run = session.get(CensusRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="census run not found")
    return {
        "id": run.id,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at is not None else None,
        "population_size": run.population_size,
        "fetch_failures": run.fetch_failures,
        "tool_version": run.tool_version,
        "method_hash": run.method_hash,
        "tier2_n": run.tier2_n,
        "registry_endpoint": run.registry_endpoint,
    }
