from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.deprecated_features import CHECK
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(
    server_capabilities: dict[str, object], client_capabilities: dict[str, object] | None = None
) -> ScanContext:
    raw: dict[str, dict[str, object]] = {"server/discover": {"capabilities": server_capabilities}}
    if client_capabilities is not None:
        raw["_config"] = {"capabilities": client_capabilities}
    return ScanContext(
        target="https://mcp.example.test",
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


def test_sampling_declared_in_client_config_is_reported_at_medium() -> None:
    findings = CHECK.run(_context({}, {"sampling": {}}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "sampling" in findings[0].title.lower()
    assert "twelve" in findings[0].title.lower() or "12" in findings[0].title


def test_roots_in_client_config_is_reported_at_low() -> None:
    findings = CHECK.run(_context({}, {"roots": {}}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_logging_is_read_from_the_server_side_not_the_client_config() -> None:
    findings = CHECK.run(_context({"logging": {}}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_roots_declared_as_a_server_capability_is_not_a_false_positive_source() -> None:
    # Recall(0) for two of three was the bug: roots/sampling on the SERVER
    # side must not be read as if they were the client-side fact.
    assert CHECK.run(_context({"roots": {}, "sampling": {}})) == []


def test_clean_server_reports_nothing() -> None:
    assert CHECK.run(_context({"tools": {}, "extensions": {}})) == []


def test_every_finding_cites_the_deprecation_source() -> None:
    for finding in CHECK.run(_context({"logging": {}}, {"sampling": {}, "roots": {}})):
        assert "mcp-spec:2026-07-28-changelog" in finding.taxonomy_refs
        assert finding.cwe == "CWE-477"


def test_absent_discover_response_yields_nothing() -> None:
    context = ScanContext(
        target="t",
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
    )
    assert CHECK.run(context) == []
