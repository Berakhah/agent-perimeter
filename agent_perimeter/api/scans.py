# agent_perimeter/api/scans.py
"""POST /api/scans and its status/findings/graph/report.sarif/events reads.

`require_scope` is called directly, synchronously, in `create_scan` below —
the same function `scan_runner.run_scan` calls again at the top of the
pipeline itself, and the same function every active check calls. One
implementation; calling it from two sites doesn't create a second one, the
same way calling `len()` twice isn't two length-counting implementations.
The synchronous call here is what makes the refusal a 422 on the POST
response itself (tests/api/test_refusal.py), not an async failure a client
would have to poll for.
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse

from agent_perimeter.api.schemas import ScanRequest, ScopeFileInput
from agent_perimeter.api.state import AppState
from agent_perimeter.db.models import CapabilityEdge as CapabilityEdgeRow
from agent_perimeter.db.models import FindingRow, Scan, Tool
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope
from agent_perimeter.report.sarif import to_sarif
from agent_perimeter.scan_runner import EventFrame, ScanMode, ScanOutcome, run_scan

logger = logging.getLogger(__name__)

router = APIRouter()

# Any container running this API never mounts docker.sock (Task 9 ruling
# #9/pre-flight-scan row 9) — a stdio target is a command to launch, and
# only the CLI's own containerised launcher (Week 1 hard constraint 4) is
# entitled to do that. The API classifies before any transport/container
# logic runs at all.
_SUPPORTED_SCHEMES = ("http://", "https://")


def _build_scope(raw: ScopeFileInput | None, *, today: date) -> ScopeFile | None:
    """Structural absence, checked in the request schema's own field order —
    target, authorising_party, attestation (authorised_on is defaulted, Task
    9 ruling #7) — *before* handing off to the real `ScopeFile` and
    `require_scope`'s semantic checks (target mismatch, not-yet-authorised,
    expired). Same exception type, same handler, either way.
    """
    if raw is None:
        return None
    target = raw.target
    if target is None:
        raise AuthorizationRequired("scope_file.target is required.", missing_field="target")
    authorising_party = raw.authorising_party
    if authorising_party is None:
        raise AuthorizationRequired(
            "scope_file.authorising_party is required.", missing_field="authorising_party"
        )
    attestation = raw.attestation
    if attestation is None:
        raise AuthorizationRequired(
            "scope_file.attestation is required.", missing_field="attestation"
        )
    return ScopeFile(
        target=target,
        authorising_party=authorising_party,
        authorised_on=raw.authorised_on if raw.authorised_on is not None else today,
        attestation=attestation,
        expires_on=raw.expires_on,
    )


@router.post("/scans", status_code=202)
def create_scan(
    scan_request: ScanRequest, background_tasks: BackgroundTasks, request: Request
) -> dict[str, object]:
    if not scan_request.target.startswith(_SUPPORTED_SCHEMES):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_target",
                "message": (
                    f"{scan_request.target!r} is not an http(s) target. This API only "
                    "accepts http(s) MCP servers. Scan a stdio target with the CLI "
                    "instead: agent-perimeter scan --target ..."
                ),
            },
        )

    today = date.today()
    scope = _build_scope(scan_request.scope_file, today=today)
    if scan_request.mode is ScanMode.ACTIVE:
        require_scope(scope, check_id="scan", target=scan_request.target, today=today)

    state: AppState = request.app.state.ap
    scan_id = str(uuid.uuid4())
    state.events.start(scan_id)
    with state.lock:
        state.requests[scan_id] = scan_request

    background_tasks.add_task(_run_and_record, scan_id, scan_request, scope, state)
    return {"id": scan_id, "status": "accepted"}


def _run_and_record(
    scan_id: str, scan_request: ScanRequest, scope: ScopeFile | None, state: AppState
) -> None:
    event_count = 0

    def on_event(frame: EventFrame) -> None:
        nonlocal event_count
        event_count += 1
        state.events.append(scan_id, frame)

    outcome: ScanOutcome | None = None
    try:
        invocation_flags = (
            ("--mode", scan_request.mode.value) if scan_request.mode is ScanMode.ACTIVE else ()
        )
        outcome = run_scan(
            scan_request.target,
            scan_request.mode,
            scope,
            invocation_flags=invocation_flags,
            on_event=on_event,
        )
    except Exception:  # noqa: BLE001 - a scan that raises still gets a terminal frame.
        logger.exception("scan %s failed", scan_id)
        state.events.finish(scan_id, skipped=[], completed=event_count, total=event_count)
        return

    with state.lock:
        state.results[scan_id] = outcome
    state.events.finish(
        scan_id,
        skipped=outcome.skipped,
        completed=event_count,
        total=event_count + len(outcome.skipped),
    )
    _persist(state, scan_id, scan_request, outcome)


def _persist(
    state: AppState, scan_id: str, scan_request: ScanRequest, outcome: ScanOutcome
) -> None:
    """Durability/audit only (Task 9 ruling #5) — never the read path for
    findings/graph/report.sarif/status, all served from the in-process cache
    above. Best-effort: a database that is unreachable must not take the
    scan itself down, so failures here are logged, not raised.
    """
    try:
        with state.session_factory() as session:
            revision = outcome.fingerprint.revision_claimed
            scan_row = Scan(
                id=scan_id,
                target_ref=scan_request.target,
                revision_claimed=revision.value if revision is not None else None,
                feature_set_json=sorted(f.value for f in outcome.fingerprint.features),
                finished_at=datetime.now(UTC),
                mode=scan_request.mode.value,
                tool_version="0.1.0",
            )
            session.add(scan_row)

            tool_ids: dict[str, str] = {}
            for tool in outcome.tools:
                tool_row = Tool(
                    scan_id=scan_id,
                    name=tool.name,
                    description_hash=hashlib.sha256(tool.description.encode()).hexdigest(),
                    input_schema_json=tool.input_schema,
                    annotations_json=tool.annotations,
                )
                session.add(tool_row)
                session.flush()
                tool_ids[tool.name] = tool_row.id

            for edge in outcome.edges:
                tool_id = tool_ids.get(edge.tool)
                if tool_id is None:
                    continue
                session.add(
                    CapabilityEdgeRow(
                        tool_id=tool_id,
                        capability=edge.capability.value,
                        derived_from=edge.derivation.value,
                        claim_json=json.loads(edge.claim.model_dump_json()),
                    )
                )

            for finding in outcome.findings:
                session.add(
                    FindingRow(
                        scan_id=scan_id,
                        check_id=finding.check_id,
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        cwe=finding.cwe,
                        taxonomy_refs_json=list(finding.taxonomy_refs),
                        title=finding.title,
                        reproduction=finding.reproduction,
                        claim_json=json.loads(finding.claim.model_dump_json()),
                    )
                )
            session.commit()
    except Exception:  # noqa: BLE001 - see docstring: best-effort, never fatal.
        logger.warning("could not persist scan %s to the database", scan_id, exc_info=True)


@dataclass(frozen=True)
class _ScanState:
    status: str  # "running" | "completed" | "errored"
    outcome: ScanOutcome | None


def _scan_state(state: AppState, scan_id: str) -> _ScanState:
    frames = state.events.frames(scan_id)
    if frames is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not state.events.is_done(scan_id):
        return _ScanState(status="running", outcome=None)
    with state.lock:
        outcome = state.results.get(scan_id)
    return _ScanState(status="completed" if outcome is not None else "errored", outcome=outcome)


def _require_outcome(state: AppState, scan_id: str) -> ScanOutcome:
    scan_state = _scan_state(state, scan_id)
    if scan_state.status == "running":
        raise HTTPException(status_code=409, detail="scan is still running")
    if scan_state.outcome is None:
        raise HTTPException(status_code=500, detail="scan errored before producing a result")
    return scan_state.outcome


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, request: Request) -> dict[str, object]:
    state: AppState = request.app.state.ap
    scan_state = _scan_state(state, scan_id)
    body: dict[str, object] = {"id": scan_id, "status": scan_state.status}
    if scan_state.outcome is not None:
        outcome = scan_state.outcome
        revision = outcome.fingerprint.revision_claimed
        body |= {
            "revision_claimed": revision.value if revision is not None else None,
            "features_observed": sorted(f.value for f in outcome.fingerprint.features),
            "findings_count": len(outcome.findings),
            "skipped_count": len(outcome.skipped),
            "errored_count": len(outcome.errored),
        }
    return body


@router.get("/scans/{scan_id}/findings")
def get_findings(scan_id: str, request: Request) -> list[dict[str, object]]:
    state: AppState = request.app.state.ap
    outcome = _require_outcome(state, scan_id)
    return list(jsonable_encoder(outcome.findings))


@router.get("/scans/{scan_id}/graph")
def get_graph(scan_id: str, request: Request) -> list[dict[str, object]]:
    state: AppState = request.app.state.ap
    outcome = _require_outcome(state, scan_id)
    return list(jsonable_encoder(outcome.edges))


@router.get("/scans/{scan_id}/report.sarif")
def get_sarif(scan_id: str, request: Request) -> dict[str, object]:
    state: AppState = request.app.state.ap
    outcome = _require_outcome(state, scan_id)
    with state.lock:
        scan_request = state.requests[scan_id]
    # to_sarif() writes a scan-profile artifact (the real bytes a finding
    # with no FindingLocation of its own is anchored to) into `workspace` --
    # a per-scan scratch directory, not the server's cwd, since an API
    # process has no "the repo being scanned" the way the CLI's own
    # --sarif does.
    workspace = Path(tempfile.gettempdir()) / "agent-perimeter-api" / scan_id
    return to_sarif(
        outcome.findings,
        target=scan_request.target,
        tool_version="0.1.0",
        fingerprint=outcome.fingerprint,
        workspace=workspace,
    )


@router.get("/scans/{scan_id}/events")
def get_events(scan_id: str, request: Request) -> StreamingResponse:
    state: AppState = request.app.state.ap
    if state.events.frames(scan_id) is None:
        raise HTTPException(status_code=404, detail="scan not found")

    def _generate() -> Iterator[str]:
        # ponytail: polling, not a push/subscribe channel -- fine at this
        # scale (one process, a handful of concurrent scans); move to an
        # async condition variable or queue if poll interval or connection
        # count ever matters. Under TestClient the background task has
        # already finished by the time this generator starts (Starlette
        # runs BackgroundTasks before the ASGI call returns to the test
        # client), so this loop sends every frame and exits on its first
        # pass without ever sleeping.
        sent = 0
        while True:
            frames = state.events.frames(scan_id) or []
            for frame in frames[sent:]:
                yield f"data: {json.dumps(frame)}\n\n"
            sent = len(frames)
            if state.events.is_done(scan_id):
                break
            time.sleep(0.1)

    return StreamingResponse(_generate(), media_type="text/event-stream")
