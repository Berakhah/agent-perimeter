from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.registry import Skipped, SkipReason
from agent_perimeter.eval.score import CheckScore
from agent_perimeter.model.edge import Capability, CapabilityEdge
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding
from agent_perimeter.report.html import render_report
from agent_perimeter.transport.revision import Fingerprint

FINGERPRINT = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER, Feature.RESULT_TYPE}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime(2026, 9, 1, tzinfo=UTC),
    ),
)

FINDING = Finding(
    check_id="revision.cache_scope",
    severity=Severity.MEDIUM,
    title="Tool listing is marked publicly cacheable",
    cwe="CWE-524",
    taxonomy_refs=("owasp-llm:LLM02",),
    evidence=Evidence(kind=EvidenceKind.EXCERPT, excerpt='"cacheScope": "public"'),
    reproduction="agent-perimeter scan --target $T --only revision.cache_scope",
    claim=Claim(
        value="public",
        method=Method.DETERMINISTIC,
        derivation=Derivation.SCHEMA,
        observed_at=datetime(2026, 9, 1, tzinfo=UTC),
    ),
)

EDGE = CapabilityEdge(
    tool="fetch",
    capability=Capability.NET_OUT,
    derivation=Derivation.SCHEMA,
    claim=FINDING.claim,
    rationale="input schema declares parameter 'url'",
)


def _render(**overrides: object) -> str:
    kwargs: dict[str, object] = {
        "findings": [FINDING],
        "edges": [EDGE],
        "fingerprint": FINGERPRINT,
        "target": "https://mcp.example.test/rpc",
        "skipped": [],
        "scores": [CheckScore("revision.cache_scope", 1, 0, 0, 1.0, 1.0, 2)],
    }
    kwargs.update(overrides)
    return render_report(**kwargs)  # type: ignore[arg-type]


def test_report_shows_the_revision_conformance_strip() -> None:
    html = _render()
    assert "claims 2026-07-28" in html
    assert "observes 2 of" in html


def test_severity_is_never_colour_alone() -> None:
    html = _render()
    assert "MEDIUM" in html


def test_every_finding_shows_its_cwe_and_reproduction() -> None:
    html = _render()
    assert "CWE-524" in html
    assert "--only revision.cache_scope" in html


def test_edge_derivation_is_rendered() -> None:
    assert "schema" in _render()


def test_skipped_checks_are_stated_not_hidden() -> None:
    skipped = [Skipped("revision.mrtr", SkipReason.FEATURE_ABSENT, "target lacks: mrtr")]
    html = _render(skipped=skipped)
    assert "revision.mrtr" in html
    assert "feature_absent" in html


def test_empty_findings_uses_the_required_copy() -> None:
    html = _render(findings=[])
    assert "No findings for the checks that ran" in html
    assert "You&#39;re secure" not in html and "You're secure" not in html


def test_methodology_footer_is_present() -> None:
    html = _render()
    assert "Methodology" in html
    assert "precision" in html.lower()


def test_print_stylesheet_is_inlined() -> None:
    assert "@media print" in _render()
