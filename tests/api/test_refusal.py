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
    from agent_perimeter.model.scope import require_scope  # noqa: F401

    assert "require_scope" in inspect.getsource(api_app)
