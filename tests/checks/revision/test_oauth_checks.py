from datetime import UTC, datetime

import httpx

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision import issuer_validation, registration_mode
from agent_perimeter.checks.revision.oauth_metadata import fetch_oauth_metadata
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(metadata: dict[str, object] | None) -> ScanContext:
    raw: dict[str, dict[str, object]] = {}
    if metadata is not None:
        raw["oauth/metadata"] = metadata
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.SERVER_DISCOVER}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw=raw,
    )


def test_dcr_without_cimd_is_reported() -> None:
    metadata = {"registration_endpoint": "https://as.example.test/register"}
    findings = registration_mode.CHECK.run(_context(metadata))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-477"
    assert findings[0].severity is Severity.LOW


def test_cimd_support_makes_dcr_acceptable() -> None:
    metadata = {
        "registration_endpoint": "https://as.example.test/register",
        "client_id_metadata_document_supported": True,
    }
    assert registration_mode.CHECK.run(_context(metadata)) == []


def test_missing_iss_support_is_reported() -> None:
    findings = issuer_validation.CHECK.run(_context({"issuer": "https://as.example.test"}))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-346"
    assert "rfc:9207" in findings[0].taxonomy_refs


def test_declared_iss_support_is_clean() -> None:
    metadata = {
        "issuer": "https://as.example.test",
        "authorization_response_iss_parameter_supported": True,
    }
    assert issuer_validation.CHECK.run(_context(metadata)) == []


def test_no_oauth_metadata_means_no_findings() -> None:
    assert registration_mode.CHECK.run(_context(None)) == []
    assert issuer_validation.CHECK.run(_context(None)) == []


def test_fetch_returns_none_on_404() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert fetch_oauth_metadata("https://mcp.example.test/rpc", client=client) is None


def test_fetch_parses_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/oauth-authorization-server"
        return httpx.Response(200, json={"issuer": "https://as.example.test"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    metadata = fetch_oauth_metadata("https://mcp.example.test/rpc", client=client)
    assert metadata == {"issuer": "https://as.example.test"}
