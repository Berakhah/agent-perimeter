"""The published taxonomy entries this scanner is allowed to cite.

A finding citing an entry not registered here fails the test suite. That is
deliberate: an uncitable finding must not be shippable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

TAXONOMY_YAML = Path(__file__).parent / "taxonomy.yaml"


class UnknownTaxonomyRef(KeyError):
    """A finding cited a taxonomy entry that is not registered."""


@dataclass(frozen=True)
class TaxonomyEntry:
    scheme: str
    id: str
    title: str
    url: str


def _load(path: Path = TAXONOMY_YAML) -> dict[str, TaxonomyEntry]:
    rows: list[dict[str, str]] = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries: dict[str, TaxonomyEntry] = {}
    for row in rows:
        entry = TaxonomyEntry(
            scheme=row["scheme"], id=str(row["id"]), title=row["title"], url=row["url"]
        )
        entries[f"{entry.scheme}:{entry.id}"] = entry
    return entries


TAXONOMY: dict[str, TaxonomyEntry] = _load()


def resolve(ref: str) -> TaxonomyEntry:
    try:
        return TAXONOMY[ref]
    except KeyError as exc:
        msg = f"{ref} is not a registered taxonomy entry. Add it to taxonomy.yaml."
        raise UnknownTaxonomyRef(msg) from exc


# DoD 2's approved schemes. mcp-spec and rfc are useful supplementary citations
# but do not by themselves satisfy "a published taxonomy entry" — see revision
# 2026-08-29 section 2.7.
APPROVED_SCHEMES: frozenset[str] = frozenset(
    {"owasp-llm", "owasp-mcp", "cosai", "nsa-csi", "mitre-atlas"}
)


def has_approved_citation(refs: tuple[str, ...]) -> bool:
    return any(ref.split(":", 1)[0] in APPROVED_SCHEMES for ref in refs)


class UnknownCwe(KeyError):
    """A finding cited a CWE that is not registered."""


@dataclass(frozen=True)
class CweEntry:
    id: str
    title: str
    url: str


# Registered so an unresolvable CWE is caught the same way an unresolvable
# taxonomy ref is. Extend this table as Tasks 5-22 cite new CWEs.
CWE_TABLE: dict[str, CweEntry] = {
    entry.id: entry
    for entry in (
        CweEntry("CWE-113", "HTTP Response Splitting", "https://cwe.mitre.org/data/definitions/113.html"),
        CweEntry("CWE-200", "Exposure of Sensitive Information", "https://cwe.mitre.org/data/definitions/200.html"),
        CweEntry("CWE-250", "Execution with Unnecessary Privileges", "https://cwe.mitre.org/data/definitions/250.html"),
        CweEntry("CWE-284", "Improper Access Control", "https://cwe.mitre.org/data/definitions/284.html"),
        CweEntry("CWE-306", "Missing Authentication for Critical Function", "https://cwe.mitre.org/data/definitions/306.html"),
        CweEntry("CWE-319", "Cleartext Transmission of Sensitive Information", "https://cwe.mitre.org/data/definitions/319.html"),
        CweEntry("CWE-345", "Insufficient Verification of Data Authenticity", "https://cwe.mitre.org/data/definitions/345.html"),
        CweEntry("CWE-346", "Origin Validation Error", "https://cwe.mitre.org/data/definitions/346.html"),
        CweEntry("CWE-440", "Expected Behavior Violation", "https://cwe.mitre.org/data/definitions/440.html"),
        CweEntry("CWE-441", "Unintended Proxy or Intermediary", "https://cwe.mitre.org/data/definitions/441.html"),
        CweEntry("CWE-477", "Use of Obsolete Function", "https://cwe.mitre.org/data/definitions/477.html"),
        CweEntry("CWE-522", "Insufficiently Protected Credentials", "https://cwe.mitre.org/data/definitions/522.html"),
        CweEntry("CWE-524", "Use of Cache Containing Sensitive Information", "https://cwe.mitre.org/data/definitions/524.html"),
        CweEntry("CWE-613", "Insufficient Session Expiration", "https://cwe.mitre.org/data/definitions/613.html"),
        CweEntry("CWE-664", "Improper Control of a Resource Through its Lifetime", "https://cwe.mitre.org/data/definitions/664.html"),
        CweEntry("CWE-674", "Uncontrolled Recursion", "https://cwe.mitre.org/data/definitions/674.html"),
        CweEntry("CWE-798", "Use of Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html"),
        CweEntry("CWE-918", "Server-Side Request Forgery (SSRF)", "https://cwe.mitre.org/data/definitions/918.html"),
        CweEntry("CWE-1007", "Insufficient Visual Distinction of Homoglyphs", "https://cwe.mitre.org/data/definitions/1007.html"),
        CweEntry("CWE-1427", "Improper Neutralization of Input Used for LLM Prompting", "https://cwe.mitre.org/data/definitions/1427.html"),
    )
}


def resolve_cwe(cwe: str) -> CweEntry:
    try:
        return CWE_TABLE[cwe]
    except KeyError as exc:
        msg = f"{cwe} is not a registered CWE. Add it to CWE_TABLE in taxonomy.py."
        raise UnknownCwe(msg) from exc
