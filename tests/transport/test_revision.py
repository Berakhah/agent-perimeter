import importlib.util
from pathlib import Path
from typing import Any

import pytest

from agent_perimeter._contracts import Derivation, Method
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.revision import fingerprint


class FakeTransport:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.calls.append(method)
        if method not in self._responses:
            msg = f"Method not found: {method}"
            raise TransportError(msg)
        result: dict[str, object] = self._responses[method]
        return result

    def close(self) -> None: ...


MODERN_DISCOVER = {
    "resultType": "complete",
    "protocolVersions": ["2026-07-28"],
    "capabilities": {"tools": {}, "extensions": {}},
}
MODERN_TOOLS = {"resultType": "complete", "ttlMs": 60000, "cacheScope": "private", "tools": []}


def test_modern_server_is_fingerprinted_from_discover() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert result.revision_claimed is Revision.R2026_07_28
    assert Feature.SERVER_DISCOVER in result.features
    assert Feature.RESULT_TYPE in result.features
    assert Feature.CACHEABLE_RESULT in result.features
    assert Feature.EXTENSIONS in result.features


def test_legacy_server_falls_back_to_initialize() -> None:
    transport = FakeTransport(
        {
            "initialize": {"protocolVersion": "2025-11-25", "capabilities": {}},
            "tools/list": {"tools": []},
        }
    )
    result = fingerprint(transport)
    assert result.revision_claimed is Revision.R2025_11_25
    assert Feature.INITIALIZE_HANDSHAKE in result.features
    assert Feature.SERVER_DISCOVER not in result.features
    assert transport.calls[0] == "server/discover"


def test_claim_and_observation_can_disagree() -> None:
    """A server claiming 2026-07-28 without resultType is non-conformant.

    The fingerprinter records both without reconciling them. Week 2's
    conformance_mismatch check is what reports the disagreement.
    """
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": {"tools": []}})
    )
    assert result.revision_claimed is Revision.R2026_07_28
    assert Feature.RESULT_TYPE not in result.features
    assert Feature.CACHEABLE_RESULT not in result.features


def test_discover_alone_does_not_grant_unobservable_features() -> None:
    """MRTR and SUBSCRIPTIONS_LISTEN cannot be observed passively — the first
    needs a multi-step probe, the second an open stream. SESSION_HEADER is an
    HTTP-only property with no channel to see it through here. A server
    answering server/discover must not cause any of them to be granted.
    """
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert Feature.MRTR not in result.features
    assert Feature.SUBSCRIPTIONS_LISTEN not in result.features
    assert Feature.SESSION_HEADER not in result.features


def test_unresponsive_server_yields_unknown_revision() -> None:
    result = fingerprint(FakeTransport({"tools/list": {"tools": []}}))
    assert result.revision_claimed is None
    assert result.claim.caveat == "Server answered neither server/discover nor initialize."


def test_fingerprint_carries_a_probe_derived_claim() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert result.claim.method is Method.DETERMINISTIC
    assert result.claim.derivation is Derivation.PROBE


def test_unknown_revision_string_gets_an_honest_caveat_naming_it() -> None:
    transport = FakeTransport(
        {"server/discover": {"protocolVersions": ["2027-01-01"]}, "tools/list": {}}
    )
    result = fingerprint(transport)
    assert result.revision_claimed is None
    assert result.protocol_versions_advertised == ("2027-01-01",)
    assert "2027-01-01" in (result.claim.caveat or "")
    assert "neither" not in (result.claim.caveat or "")


def test_known_older_revision_gets_an_accurate_caveat_not_the_no_response_lie() -> None:
    """2025-06-18 predates this scanner's two recognised Revision members,
    but the server did answer — the caveat must say so, never claim silence.
    """
    transport = FakeTransport(
        {
            "initialize": {"protocolVersion": "2025-06-18", "capabilities": {}},
            "tools/list": {"tools": []},
        }
    )
    result = fingerprint(transport)
    assert result.revision_claimed is None
    assert result.protocol_versions_advertised == ("2025-06-18",)
    assert Feature.INITIALIZE_HANDSHAKE in result.features
    assert "2025-06-18" in (result.claim.caveat or "")
    assert "neither" not in (result.claim.caveat or "")


def test_discover_error_code_is_captured_for_week_2s_conformance_check() -> None:
    """-32042 is a unique fingerprint for 2025-11-25 and -32001/-32003/-32004
    fingerprint a pre-final release-candidate build (revision §2.3) — Week
    2's revision.error_code_conformance is built on this field, so Week 1
    only has to prove the code survives to the Fingerprint.
    """

    class ErroringTransport:
        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            if method == "server/discover":
                raise TransportError("Method not found", code=-32601)
            if method == "initialize":
                return {"protocolVersion": "2025-11-25", "capabilities": {}}
            return {"tools": []}

        def close(self) -> None: ...

    result = fingerprint(ErroringTransport())
    assert result.discover_error_code == -32601


def test_param_headers_is_observed_from_a_real_annotation_not_a_property_named_for_it() -> None:
    """x-mcp-header is an annotation inside a parameter's own schema — its
    value is the header-name suffix — not a property that happens to be
    named x-mcp-header."""
    tools_with_annotation = {
        "resultType": "complete",
        "tools": [
            {
                "name": "get_weather",
                "inputSchema": {
                    "type": "object",
                    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                },
            }
        ],
    }
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": tools_with_annotation})
    )
    assert Feature.PARAM_HEADERS in result.features


def test_param_headers_is_absent_when_no_property_carries_the_annotation() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert Feature.PARAM_HEADERS not in result.features


class _InProcessTransport:
    """Adapts the Task-6 fixture's handle() into a Transport. No Docker
    required — this is what lets the integration test below run fast."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self._next_id = 1

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        request_id = self._next_id
        self._next_id += 1
        reply = self._handle(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        if "error" in reply:
            code = reply["error"].get("code") if isinstance(reply["error"], dict) else None
            raise TransportError(f"{method}: {reply['error']}", code=code)
        result: dict[str, object] = reply["result"]
        return result

    def close(self) -> None: ...


FIXTURE = Path(__file__).parents[1] / "fixtures" / "servers" / "server.py"


def _load_fixture(revision: str, flaw: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AP_FIXTURE_REVISION", revision)
    monkeypatch.setenv("AP_FIXTURE_FLAW", flaw)
    spec = importlib.util.spec_from_file_location(f"fx_{revision}_{flaw}", FIXTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("revision", "flaw", "expected"),
    [
        (
            "2026-07-28",
            "none",
            frozenset(
                {
                    Feature.SERVER_DISCOVER,
                    Feature.EXTENSIONS,
                    Feature.RESULT_TYPE,
                    Feature.CACHEABLE_RESULT,
                }
            ),
        ),
        (
            "2026-07-28",
            "cache_scope_public",
            frozenset(
                {
                    Feature.SERVER_DISCOVER,
                    Feature.EXTENSIONS,
                    Feature.RESULT_TYPE,
                    Feature.CACHEABLE_RESULT,
                }
            ),
        ),
        (
            "2026-07-28",
            "missing_result_type",
            frozenset(
                {
                    Feature.SERVER_DISCOVER,
                    Feature.EXTENSIONS,
                    Feature.CACHEABLE_RESULT,
                }
            ),
        ),
        (
            # The fixture's param_header flaw adds a *property named*
            # x-mcp-header rather than annotating an existing one — the
            # wrong shape per revision §1.8, left for Week 2's fixture-matrix
            # pass to correct. PARAM_HEADERS must stay absent against it:
            # this proves the detector has no false positive on that shape.
            "2026-07-28",
            "param_header",
            frozenset(
                {
                    Feature.SERVER_DISCOVER,
                    Feature.EXTENSIONS,
                    Feature.RESULT_TYPE,
                    Feature.CACHEABLE_RESULT,
                }
            ),
        ),
        ("2025-11-25", "none", frozenset({Feature.INITIALIZE_HANDSHAKE})),
    ],
)
def test_fingerprint_against_the_real_fixture_asserts_the_feature_set_exactly(
    revision: str, flaw: str, expected: frozenset[Feature], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No feature is ever asserted that the fixture did not actually
    produce. This runs the real fingerprint(), not a hand-built Fingerprint
    — the eval-harness defect the revision describes (§4.3) is exactly a
    suite that stopped doing this."""
    module = _load_fixture(revision, flaw, monkeypatch)
    result = fingerprint(_InProcessTransport(module.handle))
    assert result.features == expected
