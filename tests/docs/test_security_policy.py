import re
from pathlib import Path

POLICY = Path("docs/security.md")
REQUIRED_SECTIONS = [
    "## Reporting a vulnerability in Agent Perimeter",
    "## What we do when we find something in your server",
    "## Embargo",
    "## Right of reply",
    "## Secrets",
    "## What we publish",
    "## Digest salt release",
]


def test_every_required_section_is_present() -> None:
    body = POLICY.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in body, f"missing: {section}"


def test_the_embargo_length_matches_the_decision() -> None:
    assert "90 days" in POLICY.read_text(encoding="utf-8")


def test_secrets_bypass_the_embargo_clock() -> None:
    body = POLICY.read_text(encoding="utf-8").lower()
    assert "never publish" in body and "never validate" in body


def test_root_pointer_carries_the_same_contact() -> None:
    contact = re.search(r"<([^>]+@[^>]+)>", POLICY.read_text(encoding="utf-8"))
    assert contact is not None
    assert contact.group(1) in Path("SECURITY.md").read_text(encoding="utf-8")
