"""Happy-path and stdio-refusal coverage for the /api/scans surface.

test_refusal.py (brief-mandated, verbatim) covers the authorisation refusal
itself. This file covers what it doesn't: a passive scan actually completing
end to end through the HTTP surface (status lookup, findings, graph, SARIF,
the SSE event stream including its terminal `skipped` frame), an active scan
with a *valid* scope file being accepted and completing, and the stdio-target
400 refusal from Task 9 ruling #3/pre-flight-scan row 9.

Every test here stubs `scan_runner.fingerprint`/`scan_runner.build_transport`
(mirroring tests/test_cli.py's `stub_fingerprint` fixture) so nothing makes a
real network call — unlike test_refusal.py's own passive-mode test, which
necessarily does (its target and content are verbatim from the brief).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.api.app import create_app
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint

TARGET = "https://mcp.example.test/rpc"

MODERN = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER, Feature.RESULT_TYPE}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime.now(UTC),
    ),
)


class _FakeTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


@pytest.fixture
def stub_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_perimeter.scan_runner.fingerprint", lambda transport: MODERN)
    monkeypatch.setattr(
        "agent_perimeter.scan_runner.build_transport",
        lambda target, image, env: _FakeTransport(),
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.revision.oauth_metadata.fetch_oauth_metadata",
        lambda target, **kwargs: None,
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.static.auth_probe.probe_auth_challenge",
        lambda target, **kwargs: {},
    )


@pytest.fixture
def client(tmp_path: Path, stub_pipeline: None) -> Iterator[TestClient]:
    # A real file-backed sqlite (not `sqlite://` in-memory): the API's own
    # engine is shared across the request thread and the BackgroundTasks
    # thread, and an in-memory sqlite database is per-connection unless
    # StaticPool is wired up -- a file avoids that entirely.
    db_path = tmp_path / "api.db"
    with TestClient(create_app(database_url=f"sqlite:///{db_path}")) as c:
        yield c


def _post_passive(client: TestClient, target: str = TARGET) -> str:
    r = client.post("/api/scans", json={"target": target, "mode": "passive"})
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    assert isinstance(scan_id, str)
    return scan_id


def test_a_passive_scan_completes_and_status_reports_it(client: TestClient) -> None:
    scan_id = _post_passive(client)

    r = client.get(f"/api/scans/{scan_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["revision_claimed"] == "2026-07-28"
    assert "server_discover" in body["features_observed"]
    assert body["findings_count"] >= 0
    assert body["skipped_count"] >= 0


def test_findings_graph_and_sarif_are_retrievable_once_complete(client: TestClient) -> None:
    scan_id = _post_passive(client)

    findings = client.get(f"/api/scans/{scan_id}/findings")
    assert findings.status_code == 200
    assert isinstance(findings.json(), list)

    graph = client.get(f"/api/scans/{scan_id}/graph")
    assert graph.status_code == 200
    assert isinstance(graph.json(), list)

    sarif = client.get(f"/api/scans/{scan_id}/report.sarif")
    assert sarif.status_code == 200
    document = sarif.json()
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "agent-perimeter"


def test_event_stream_carries_a_terminal_frame_with_skipped(client: TestClient) -> None:
    scan_id = _post_passive(client)

    r = client.get(f"/api/scans/{scan_id}/events")
    assert r.status_code == 200
    lines = [line for line in r.text.split("\n\n") if line.strip()]
    frames = [json.loads(line.removeprefix("data: ")) for line in lines]

    assert frames, "expected at least the terminal frame"
    terminal = frames[-1]
    assert terminal["terminal"] is True
    assert "skipped" in terminal
    # A passive scan against a features-poor fixture always skips *something*
    # -- the four active/* checks and revision.header_body_mismatch all
    # require_auth, and there is no scope file at all in passive mode.
    assert terminal["skipped"], "passive mode must skip every requires_auth check"
    assert all({"check_id", "reason", "detail"} <= frame.keys() for frame in terminal["skipped"])
    assert terminal["completed"] + len(terminal["skipped"]) == terminal["total"]


def test_a_stdio_target_is_refused_with_a_400_naming_the_cli(client: TestClient) -> None:
    r = client.post("/api/scans", json={"target": "python /server.py", "mode": "passive"})
    assert r.status_code == 400
    body = r.json()["detail"]
    assert body["error"] == "unsupported_target"
    assert "agent-perimeter scan" in body["message"]


def test_an_unknown_scan_id_is_404_everywhere(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/scans/{missing}").status_code == 404
    assert client.get(f"/api/scans/{missing}/findings").status_code == 404
    assert client.get(f"/api/scans/{missing}/graph").status_code == 404
    assert client.get(f"/api/scans/{missing}/report.sarif").status_code == 404
    assert client.get(f"/api/scans/{missing}/events").status_code == 404


def test_active_mode_with_a_valid_scope_file_is_accepted_and_completes(
    client: TestClient,
) -> None:
    scope = {
        "target": TARGET,
        "authorising_party": "Example Ltd",
        "authorised_on": "2026-08-30",
        "attestation": "I authorise active probing.",
    }
    r = client.post("/api/scans", json={"target": TARGET, "mode": "active", "scope_file": scope})
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]

    status = client.get(f"/api/scans/{scan_id}").json()
    assert status["status"] == "completed"


def test_census_run_not_found_is_404(client: TestClient) -> None:
    r = client.get("/api/census/runs/999999")
    assert r.status_code == 404
