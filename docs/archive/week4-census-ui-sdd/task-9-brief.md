### Task 9: The API

**Files:**
- Create: `agent_perimeter/api/__init__.py`
- Create: `agent_perimeter/api/app.py`
- Create: `agent_perimeter/api/schemas.py`
- Create: `agent_perimeter/api/events.py`
- Modify: `agent_perimeter/model/scope.py` (structured `missing_field` on the exception)
- Test: `tests/api/test_scans.py`
- Test: `tests/api/test_refusal.py`

**Interfaces:**
- Produces: `create_app() -> FastAPI`; routes `POST /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/events` (SSE), `GET /api/scans/{id}/findings`, `GET /api/scans/{id}/graph`, `GET /api/scans/{id}/report.sarif`, `GET /api/census/runs/{id}`.
- Consumes: the Week 1–3 scan pipeline, `ScopeFile`, `AuthorizationRequired`, `require_scope`, `to_sarif`, `build_graph`.

The API's job is to expose what already works, not to reimplement it. One rule matters: **the refusal path must be identical to the CLI's.** If the UI can start an active scan that the CLI would refuse, the scope-file constraint has a hole in it, and the hole is in the surface a buyer actually clicks.

**One additive change to Week 1 Task 3 is needed first.** `AuthorizationRequired` currently carries the failing field name only inside its message string. The API has to put that field in a JSON body and the UI has to point at the right input, and neither should be regexing an English sentence. Add the attribute without touching the messages, so Week 1's tests keep passing unchanged:

```python
class AuthorizationRequired(Exception):
    """Raised when an active check is attempted without valid authorisation."""

    def __init__(self, message: str, *, missing_field: str) -> None:
        super().__init__(message)
        self.missing_field = missing_field
```

Then pass `missing_field="scope_file"`, `"target"`, `"expires_on"` or `"attestation"` at each of `require_scope`'s existing raise sites. Add one test to `tests/model/test_scope.py` asserting the attribute is set on every raise path — an unstructured error is the kind of thing that quietly becomes structured-ish later.

- [ ] **Step 1: RED — the refusal, first**

Create `tests/api/test_refusal.py`:

```python
from fastapi.testclient import TestClient

from agent_perimeter.api.app import create_app

client = TestClient(create_app())


def test_active_mode_without_a_scope_file_is_refused() -> None:
    r = client.post("/api/scans", json={"target": "https://example.invalid/mcp", "mode": "active"})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "authorization_required"
    assert body["missing_field"]
    assert "scope file" in body["message"].lower()


def test_the_refusal_names_the_specific_missing_attestation_field() -> None:
    scope = {"target": "https://example.invalid/mcp", "authorising_party": "Acme Ltd"}
    r = client.post(
        "/api/scans",
        json={"target": "https://example.invalid/mcp", "mode": "active", "scope_file": scope},
    )
    assert r.status_code == 422
    assert r.json()["missing_field"] == "attestation"


def test_passive_mode_needs_no_scope_file() -> None:
    r = client.post("/api/scans", json={"target": "https://example.invalid/mcp", "mode": "passive"})
    assert r.status_code == 202


def test_the_api_and_the_cli_refuse_on_the_same_condition() -> None:
    """One authorisation rule, one implementation. Two would eventually disagree."""
    import inspect

    from agent_perimeter.api import app as api_app
    from agent_perimeter.model.scope import require_scope

    assert "require_scope" in inspect.getsource(api_app)
```

Run: `uv run pytest tests/api/`
Expected: `ModuleNotFoundError: agent_perimeter.api.app`

- [ ] **Step 2: GREEN — the app**

Create `agent_perimeter/api/app.py`:

```python
"""HTTP surface over the existing scan pipeline. It adds no security decisions."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_perimeter.model.scope import AuthorizationRequired, require_scope


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Perimeter", docs_url="/api/docs")

    @app.exception_handler(AuthorizationRequired)
    async def _refusal(request: Request, exc: AuthorizationRequired) -> JSONResponse:
        # Copy rule: what happened, what to do, no apology.
        return JSONResponse(
            status_code=422,
            content={
                "error": "authorization_required",
                "missing_field": exc.missing_field,
                "message": (
                    f"Active checks need a scope file with {exc.missing_field}. "
                    "Attach one and re-run."
                ),
            },
        )

    app.include_router(scans.router, prefix="/api")
    app.include_router(census.router, prefix="/api")
    return app
```

`POST /api/scans` calls `require_scope(...)` for active mode before enqueuing anything — the same function the CLI and every active check call. No second implementation exists.

- [ ] **Step 3: The event stream**

`GET /api/scans/{id}/events` emits SSE frames, one per check completion:

```json
{"check_id": "revision.cache_scope", "status": "passed", "elapsed_ms": 41,
 "phase": "revision", "completed": 12, "total": 29}
```

and a terminal frame carrying `skipped` with per-check reasons. **Skipped checks are in the stream, not omitted** — spec §7.3: a skipped check is never silently absent from the count, and the live screen is where that rule is most tempting to break.

- [ ] **Step 4: Verify against a fixture**

```bash
uv run uvicorn agent_perimeter.api.app:create_app --factory --port 8000 &
curl -sS -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"python /server.py","mode":"active"}' | jq
```

Expected: `422` with `missing_field` naming the first absent attestation field. **Screenshot this** — brief §7 calls the refusal a selling point, and it belongs in the deck.

- [ ] **Step 5: Commit**

```bash
uv run pytest tests/api/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/api/ agent_perimeter/model/scope.py tests/api/ tests/model/test_scope.py
git commit -m "feat: API over the scan pipeline, refusing on the same rule as the CLI"
```

---

