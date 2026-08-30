from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.model.finding import Evidence, EvidenceKind, Finding

CLAIM = Claim(
    value=True,
    method=Method.DETERMINISTIC,
    derivation=Derivation.SCHEMA,
    observed_at=datetime.now(UTC),
)
EVIDENCE = Evidence(kind=EvidenceKind.EXCERPT, excerpt='"cacheScope": "public"')


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "check_id": "revision.cache_scope",
        "severity": Severity.MEDIUM,
        "title": "Tool listing is publicly cacheable",
        "cwe": "CWE-524",
        "taxonomy_refs": ("owasp-llm:LLM02",),
        "evidence": EVIDENCE,
        "reproduction": "agent-perimeter scan --target $TARGET --only revision.cache_scope",
        "claim": CLAIM,
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_requires_a_cwe() -> None:
    with pytest.raises(ValidationError, match="cwe"):
        _finding(cwe="")


def test_cwe_must_look_like_a_cwe_identifier() -> None:
    with pytest.raises(ValidationError, match="CWE-"):
        _finding(cwe="524")


def test_finding_requires_at_least_one_taxonomy_ref() -> None:
    with pytest.raises(ValidationError, match="taxonomy_refs"):
        _finding(taxonomy_refs=())


def test_finding_requires_a_reproduction() -> None:
    with pytest.raises(ValidationError, match="reproduction"):
        _finding(reproduction="   ")


def test_valid_finding_constructs() -> None:
    finding = _finding()
    assert finding.cwe == "CWE-524"
    assert finding.claim.derivation is Derivation.SCHEMA


def test_derivation_name_sits_between_schema_and_description() -> None:
    members = list(Derivation)
    assert (
        members.index(Derivation.SCHEMA)
        < members.index(Derivation.NAME)
        < members.index(Derivation.DESCRIPTION)
    )


# The DoD-2 citation gate in tests/checks/test_all_checks.py validates
# Check.cwe / Check.taxonomy_refs — the class-level declarations. What lands
# in a report is Finding.cwe / Finding.taxonomy_refs, set per instance, and
# the two already diverge (revision.schema_composition declares CWE-674 and
# constructs CWE-918; descriptions.shadowing declares CWE-441 and constructs
# CWE-1007; secrets.config_scan adds owasp-mcp:MCP01). Making it a
# construction-time invariant is what actually guarantees it.


def test_an_unregistered_cwe_cannot_be_constructed() -> None:
    with pytest.raises(ValidationError, match="not a registered CWE"):
        _finding(cwe="CWE-99999")


def test_an_unresolvable_taxonomy_ref_cannot_be_constructed() -> None:
    with pytest.raises(ValidationError, match="not a registered taxonomy entry"):
        _finding(taxonomy_refs=("owasp-llm:LLM99",))


def test_a_resolvable_ref_alongside_an_unresolvable_one_still_fails() -> None:
    with pytest.raises(ValidationError, match="not a registered taxonomy entry"):
        _finding(taxonomy_refs=("owasp-llm:LLM02", "made-up:XYZ"))


def test_every_cwe_a_check_actually_constructs_resolves() -> None:
    """Not just the one it declares — the per-finding values too."""
    from agent_perimeter.checks.taxonomy import resolve_cwe

    for cwe in ("CWE-918", "CWE-1007", "CWE-674", "CWE-441"):
        resolve_cwe(cwe)


# --- Evidence.excerpt is attacker-authored text ------------------------------
#
# Four checks (imperative_injection, name_schema_mismatch, shadowing,
# llm_judge) pass `tool.description` straight into Evidence. It reaches the
# SARIF message and the on-disk scan profile verbatim. descriptions.
# unicode_anomaly deliberately reports bidi/zero-width/tag characters by
# codepoint and never reproduces them; a description that trips a *different*
# check must not smuggle them out through that check's evidence instead.


def test_control_characters_are_replaced_with_their_codepoint() -> None:
    evidence = Evidence(kind=EvidenceKind.EXCERPT, excerpt="safe\u202edangerous")
    assert "\u202e" not in evidence.excerpt
    assert evidence.excerpt == "safeU+202Edangerous"


def test_zero_width_and_tag_characters_are_replaced_too() -> None:
    excerpt = Evidence(kind=EvidenceKind.EXCERPT, excerpt="a\u200bb\U000e0041c").excerpt
    assert excerpt == "aU+200BbU+E0041c"


def test_ordinary_whitespace_survives() -> None:
    """Every secrets/* excerpt is newline-delimited; mangling those would
    make the evidence unreadable for no security gain."""
    excerpt = Evidence(kind=EvidenceKind.EXCERPT, excerpt="line one\nline\ttwo\r\n").excerpt
    assert excerpt == "line one\nline\ttwo\r\n"


def test_an_oversized_excerpt_is_truncated_with_a_marker() -> None:
    from agent_perimeter.model.finding import EXCERPT_MAX_CHARS

    evidence = Evidence(kind=EvidenceKind.EXCERPT, excerpt="A" * (EXCERPT_MAX_CHARS + 5000))
    assert len(evidence.excerpt) < EXCERPT_MAX_CHARS + 100
    assert evidence.excerpt.startswith("A" * 100)
    assert "truncated" in evidence.excerpt


def test_an_excerpt_within_the_cap_is_untouched() -> None:
    text = "B" * 100
    assert Evidence(kind=EvidenceKind.EXCERPT, excerpt=text).excerpt == text
