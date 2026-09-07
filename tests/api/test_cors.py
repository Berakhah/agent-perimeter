"""CORS coverage for the FastAPI app (final-review fix wave, Critical #1).

`web/src/lib/api.ts`'s fetch()/EventSource calls are cross-origin from the
browser's point of view under docker-compose.yml's split `web`/`api`
services -- without `CORSMiddleware`, the browser blocks the response
outright and the deliverable README flow (docker compose up, open the UI,
submit a scan) fails before any application code runs.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_perimeter.api.app import create_app

client = TestClient(create_app())


def test_allowed_origin_gets_the_cors_header() -> None:
    r = client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_unrelated_origin_gets_no_cors_header() -> None:
    r = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


def test_preflight_for_the_allowed_origin_is_accepted() -> None:
    r = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"


@pytest.mark.parametrize("env_value", ["", "  ", " , "])
def test_an_empty_cors_origins_env_var_does_not_allow_every_origin(
    monkeypatch: pytest.MonkeyPatch, env_value: str
) -> None:
    # A blank/whitespace AP_CORS_ORIGINS must not split into [""] -- an empty
    # string is Starlette's wildcard-adjacent "matches everything" footgun,
    # not "no origins configured".
    monkeypatch.setenv("AP_CORS_ORIGINS", env_value)
    app = create_app(database_url="sqlite://")
    scoped_client = TestClient(app)
    r = scoped_client.get("/api/health", headers={"Origin": "http://localhost:3000"})
    assert "access-control-allow-origin" not in r.headers
