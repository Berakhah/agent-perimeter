import importlib.util
from pathlib import Path
from typing import Any

import pytest

SERVER = Path(__file__).parent / "server.py"


def _load(revision: str, flaw: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AP_FIXTURE_REVISION", revision)
    monkeypatch.setenv("AP_FIXTURE_FLAW", flaw)
    spec = importlib.util.spec_from_file_location(f"fx_{revision}_{flaw}", SERVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_modern_revision_answers_discover(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "none", monkeypatch)
    reply = mod.handle({"method": "server/discover", "id": 1})
    assert reply["result"]["protocolVersions"] == ["2026-07-28"]


def test_modern_revision_rejects_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "none", monkeypatch)
    assert "error" in mod.handle({"method": "initialize", "id": 1})


def test_legacy_revision_answers_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2025-11-25", "none", monkeypatch)
    reply = mod.handle({"method": "initialize", "id": 1})
    assert reply["result"]["protocolVersion"] == "2025-11-25"


def test_legacy_revision_rejects_discover(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2025-11-25", "none", monkeypatch)
    assert "error" in mod.handle({"method": "server/discover", "id": 1})


def test_cache_scope_flaw_is_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = _load("2026-07-28", "none", monkeypatch)
    assert clean.handle({"method": "tools/list", "id": 1})["result"]["cacheScope"] == "private"

    flawed = _load("2026-07-28", "cache_scope_public", monkeypatch)
    assert flawed.handle({"method": "tools/list", "id": 1})["result"]["cacheScope"] == "public"


def test_missing_result_type_flaw_is_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "missing_result_type", monkeypatch)
    assert "resultType" not in mod.handle({"method": "tools/list", "id": 1})["result"]
