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
