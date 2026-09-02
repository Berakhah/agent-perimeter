from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.conformance_mismatch import CHECK
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(claimed: Revision | None, observed: frozenset[Feature]) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=claimed,
            features=observed,
            claim=Claim(
                value=claimed.value if claimed else None,
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
    )


FULL_MODERN = frozenset(
    {
        Feature.SERVER_DISCOVER,
        Feature.RESULT_TYPE,
        Feature.CACHEABLE_RESULT,
        Feature.MRTR,
        Feature.PARAM_HEADERS,
        Feature.SUBSCRIPTIONS_LISTEN,
        Feature.EXTENSIONS,
    }
)


def test_fully_conformant_server_reports_nothing() -> None:
    assert CHECK.run(_context(Revision.R2026_07_28, FULL_MODERN)) == []


def test_missing_result_type_escalates_above_info() -> None:
    observed = FULL_MODERN - {Feature.RESULT_TYPE}
    findings = CHECK.run(_context(Revision.R2026_07_28, observed))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "input_required" in findings[0].title


def test_cosmetic_gap_stays_info() -> None:
    observed = FULL_MODERN - {Feature.EXTENSIONS}
    findings = CHECK.run(_context(Revision.R2026_07_28, observed))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO


def test_unknown_claimed_revision_reports_nothing() -> None:
    assert CHECK.run(_context(None, FULL_MODERN)) == []


def test_finding_names_the_missing_feature_in_evidence() -> None:
    observed = FULL_MODERN - {Feature.RESULT_TYPE}
    finding = CHECK.run(_context(Revision.R2026_07_28, observed))[0]
    assert "result_type" in finding.evidence.excerpt
    assert finding.cwe == "CWE-440"


def test_a_real_fingerprint_never_reports_mrtr_or_subscriptions_listen() -> None:
    """transport.revision.fingerprint() never sets MRTR or SUBSCRIPTIONS_LISTEN
    -- neither can be observed passively (see its own docstring). Diffing the
    full bundle against a real fingerprint's features would otherwise flag
    every single conformant 2026-07-28 server, forever, for two features this
    scanner structurally cannot check."""
    realistic = FULL_MODERN - {Feature.MRTR, Feature.SUBSCRIPTIONS_LISTEN}
    assert CHECK.run(_context(Revision.R2026_07_28, realistic)) == []
