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


def test_unicode_bidi_flaw_puts_a_bidi_override_in_the_description(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load("2026-07-28", "unicode_bidi", monkeypatch)
    tool = mod.handle({"method": "tools/list", "id": 1})["result"]["tools"][0]
    assert any(0x202A <= ord(c) < 0x202F for c in tool["description"])


def test_imperative_injection_flaw_addresses_the_model(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "imperative_injection", monkeypatch)
    tool = mod.handle({"method": "tools/list", "id": 1})["result"]["tools"][0]
    assert "ignore" in tool["description"].lower()
    assert "previous" in tool["description"].lower()


def test_verbose_description_flaw_has_no_imperative_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load("2026-07-28", "verbose_description", monkeypatch)
    tool = mod.handle({"method": "tools/list", "id": 1})["result"]["tools"][0]
    assert "ignore" not in tool["description"].lower()
    assert len(tool["description"]) > 80


def test_shadowing_flaw_adds_a_colliding_tool_name(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "shadowing", monkeypatch)
    tools = mod.handle({"method": "tools/list", "id": 1})["result"]["tools"]
    names = [t["name"] for t in tools]
    assert len(names) == 2
    assert names[0].lower().replace("-", "").replace("_", "") == names[1].lower().replace(
        "-", ""
    ).replace("_", "")
    assert names[0] != names[1]


def test_tools_call_answers_without_erroring_and_reveals_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Active probes (Task 3-6) call tools/call directly. This fixture has no
    real backend behind any tool, so every call must get a benign, constant
    refusal rather than an error -- an unhandled method previously made every
    active check raise TransportError against every corpus case once they
    were registered (Task 13)."""
    mod = _load("2026-07-28", "none", monkeypatch)
    reply = mod.handle(
        {
            "method": "tools/call",
            "id": 1,
            "params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}},
        }
    )
    assert "error" not in reply
    text = reply["result"]["content"][0]["text"]
    assert "AGENT-PERIMETER-CANARY" not in text


def test_deputy_tools_flaw_adds_a_tool_with_both_path_and_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load("2026-07-28", "deputy_tools", monkeypatch)
    tools = mod.handle({"method": "tools/list", "id": 1})["result"]["tools"]
    assert len(tools) == 2
    combined = next(t for t in tools if t["name"] == "sync_to_webhook")
    properties = combined["inputSchema"]["properties"]
    assert "path" in properties
    assert "url" in properties
