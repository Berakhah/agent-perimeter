# tests/checks/static/test_token_and_session.py
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.static import session_state, token_passthrough
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(properties: dict[str, object], *, features: frozenset[Feature]) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=features,
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        tools=[
            ToolRecord(
                name="proxy_call",
                description="Call a downstream service.",
                input_schema={"type": "object", "properties": properties},
            )
        ],
    )


MODERN = frozenset()


def test_bearer_token_parameter_with_an_outbound_destination_is_high() -> None:
    findings = token_passthrough.CHECK.run(
        _context(
            {"bearer_token": {"type": "string"}, "endpoint": {"type": "string", "format": "uri"}},
            features=MODERN,
        )
    )
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-522"
    assert findings[0].severity is Severity.HIGH


def test_secrets_manager_shaped_tool_with_no_outbound_destination_is_medium() -> None:
    # A Vault/1Password-style tool: `secret` is the whole point, and there is
    # nothing in the schema shaped like a place to forward it to.
    findings = token_passthrough.CHECK.run(
        _context({"secret": {"type": "string"}}, features=MODERN)
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_credential_shaped_names_are_recognised() -> None:
    for name in ("api_key", "apiKey", "authorization", "access_token", "secret"):
        assert token_passthrough.CHECK.run(_context({name: {"type": "string"}}, features=MODERN)), (
            name
        )


def test_ordinary_parameter_is_clean_for_token_check() -> None:
    findings = token_passthrough.CHECK.run(_context({"path": {"type": "string"}}, features=MODERN))
    assert findings == []


def test_finding_uses_name_derivation_with_reduced_confidence() -> None:
    finding = token_passthrough.CHECK.run(
        _context({"secret": {"type": "string"}}, features=MODERN)
    )[0]
    assert finding.claim.derivation is Derivation.NAME
    assert finding.confidence is not None and finding.confidence < 1.0


def test_legacy_session_parameter_after_stateless_revision_is_reported() -> None:
    findings = session_state.CHECK.run(
        _context({"mcp_session_id": {"type": "string"}}, features=MODERN)
    )
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-613"
    assert findings[0].severity is Severity.MEDIUM


def test_session_parameter_on_legacy_server_is_clean() -> None:
    legacy = frozenset({Feature.SESSION_HEADER, Feature.INITIALIZE_HANDSHAKE})
    assert (
        session_state.CHECK.run(_context({"mcp_session_id": {"type": "string"}}, features=legacy))
        == []
    )
