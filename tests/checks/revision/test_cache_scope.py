from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.cache_scope import CHECK
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(
    tools_list: dict[str, object], *, authenticated: bool = False
) -> ScanContext:
    raw: dict[str, dict[str, object]] = {"tools/list": tools_list}
    if authenticated:
        raw["oauth/metadata"] = {"issuer": "https://as.example.test"}
    return ScanContext(
        target="https://mcp.example.test",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.CACHEABLE_RESULT}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw=raw,
    )


def test_public_cache_scope_on_an_authenticated_server_is_reported_at_medium() -> None:
    findings = CHECK.run(
        _context({"cacheScope": "public", "ttlMs": 60000, "tools": []}, authenticated=True)
    )
    assert len(findings) == 1
    assert findings[0].check_id == "revision.cache_scope"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].cwe == "CWE-524"
    assert "public" in findings[0].evidence.excerpt


def test_public_cache_scope_on_an_unauthenticated_server_is_info() -> None:
    findings = CHECK.run(_context({"cacheScope": "public", "tools": []}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO


def test_private_cache_scope_is_clean() -> None:
    assert CHECK.run(_context({"cacheScope": "private", "tools": []}, authenticated=True)) == []


def test_absent_cache_scope_is_not_this_check_s_business() -> None:
    assert CHECK.run(_context({"tools": []})) == []


def test_check_declares_the_feature_it_needs() -> None:
    assert CHECK.requires_features == frozenset({Feature.CACHEABLE_RESULT})
    assert CHECK.requires_auth is False
    assert CHECK.requires_model is False


def test_finding_carries_a_runnable_reproduction() -> None:
    finding = CHECK.run(_context({"cacheScope": "public", "tools": []}))[0]
    assert finding.reproduction.startswith("agent-perimeter scan --target")
    assert "revision.cache_scope" in finding.reproduction
