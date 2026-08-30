import json
from datetime import UTC, datetime

import httpx

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.static import auth_mode
from agent_perimeter.checks.static import cleartext_target as tls
from agent_perimeter.checks.static.auth_probe import probe_auth_challenge
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(
    target: str,
    metadata: dict[str, object] | None = None,
    auth_probe: dict[str, object] | None = None,
) -> ScanContext:
    raw: dict[str, dict[str, object]] = {}
    if metadata is not None:
        raw["oauth/metadata"] = metadata
    if auth_probe is not None:
        raw["_auth_probe"] = auth_probe
    return ScanContext(
        target=target,
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


def test_unauthenticated_server_is_reported_at_high() -> None:
    # No OAuth metadata AND the recorded probe found no 401 challenge at all.
    context = _context("https://mcp.example.test/rpc", auth_probe={"status_code": 200})
    findings = auth_mode.CHECK.run(context)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-306"
    assert findings[0].severity is Severity.HIGH
    assert "200" in findings[0].evidence.excerpt  # the real observation, never fabricated text


def test_oauth_metadata_present_is_clean() -> None:
    context = _context("https://mcp.example.test/rpc", {"issuer": "https://as.example.test"})
    assert auth_mode.CHECK.run(context) == []


def test_non_oauth_challenge_is_not_a_finding() -> None:
    # A 401 naming a non-OAuth scheme (static bearer key, mTLS front door) is
    # a legitimate authentication posture this check must not flag.
    probe = {"status_code": 401, "www_authenticate": "Basic realm=internal"}
    context = _context("https://mcp.example.test/rpc", auth_probe=probe)
    assert auth_mode.CHECK.run(context) == []


def test_probe_not_run_is_not_determined_at_info() -> None:
    findings = auth_mode.CHECK.run(_context("https://mcp.example.test/rpc"))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "not determined" in findings[0].title.lower()


def test_stdio_target_is_not_an_auth_finding() -> None:
    assert auth_mode.CHECK.run(_context("python -m my_server")) == []


def test_cleartext_http_target_is_reported() -> None:
    findings = tls.CHECK.run(_context("http://mcp.example.test/rpc"))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-319"
    assert findings[0].check_id == "static.cleartext_target"


def test_https_target_is_clean() -> None:
    assert tls.CHECK.run(_context("https://mcp.example.test/rpc")) == []


def test_stdio_target_is_not_a_tls_finding() -> None:
    assert tls.CHECK.run(_context("python -m my_server")) == []


def test_probe_returns_challenge_from_401_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.read()  # body present
        body = json.loads(request.content)
        assert body["method"] == "tools/list"
        return httpx.Response(401, headers={"WWW-Authenticate": "Bearer realm=example"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = probe_auth_challenge("https://mcp.example.test/rpc", client=client)
    assert result == {"status_code": 401, "www_authenticate": "Bearer realm=example"}


def test_probe_returns_empty_dict_on_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert probe_auth_challenge("https://mcp.example.test/rpc", client=client) == {}
