import pytest

from agent_perimeter.checks.taxonomy import (
    CWE_TABLE,
    TAXONOMY,
    UnknownCwe,
    UnknownTaxonomyRef,
    has_approved_citation,
    resolve,
    resolve_cwe,
)


def test_every_entry_has_a_title_and_a_url() -> None:
    assert TAXONOMY, "taxonomy.yaml must not be empty"
    for key, entry in TAXONOMY.items():
        assert entry.title.strip(), f"{key} has no title"
        assert entry.url.startswith("https://"), f"{key} has no resolvable URL"


def test_keys_are_scheme_colon_id() -> None:
    for key, entry in TAXONOMY.items():
        assert key == f"{entry.scheme}:{entry.id}"


def test_resolve_returns_the_entry() -> None:
    key = next(iter(TAXONOMY))
    assert resolve(key).id == TAXONOMY[key].id


def test_unknown_ref_raises_and_names_the_ref() -> None:
    with pytest.raises(UnknownTaxonomyRef, match="owasp-llm:LLM99"):
        resolve("owasp-llm:LLM99")


def test_mcp_spec_alone_does_not_satisfy_dod_2() -> None:
    assert has_approved_citation(("mcp-spec:2026-07-28-changelog",)) is False


def test_an_approved_scheme_satisfies_dod_2() -> None:
    assert has_approved_citation(("mcp-spec:2026-07-28-changelog", "owasp-mcp:MCP07")) is True


def test_every_cwe_row_has_a_title_and_a_url() -> None:
    assert CWE_TABLE, "CWE_TABLE must not be empty"
    for cwe_id, entry in CWE_TABLE.items():
        assert entry.title.strip(), f"{cwe_id} has no title"
        assert entry.url.startswith("https://cwe.mitre.org/"), f"{cwe_id} has no resolvable URL"


def test_unknown_cwe_raises_and_names_it() -> None:
    with pytest.raises(UnknownCwe, match="CWE-999999"):
        resolve_cwe("CWE-999999")
