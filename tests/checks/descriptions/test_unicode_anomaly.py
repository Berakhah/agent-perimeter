from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.descriptions.unicode_anomaly import CHECK, scan_text
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(description: str, name: str = "read_file") -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset(),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        tools=[ToolRecord(name=name, description=description)],
    )


def test_bidi_override_is_detected() -> None:
    assert scan_text("safe‮txet neddih")[0][0] == "bidi_override"


def test_zero_width_is_detected() -> None:
    assert scan_text("read​file")[0][0] == "zero_width"


def test_tag_characters_are_detected() -> None:
    hidden = "".join(chr(0xE0000 + ord(c) - 0x20) for c in "evil")
    assert scan_text(f"benign{hidden}")[0][0] == "tag_character"


def test_plain_ascii_is_clean() -> None:
    assert scan_text("Read a file from the workspace.") == []


def test_finding_is_critical_and_quotes_the_codepoint() -> None:
    findings = CHECK.run(_context("safe‮txet neddih"))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cwe == "CWE-1007"
    assert "U+202E" in findings[0].evidence.excerpt


def test_tool_name_is_scanned_as_well_as_description() -> None:
    findings = CHECK.run(_context("clean text", name="read​file"))
    assert len(findings) == 1
    assert findings[0].claim.derivation is Derivation.NAME


def test_anomaly_in_description_derives_from_description() -> None:
    findings = CHECK.run(_context("safe‮txet neddih"))
    assert len(findings) == 1
    assert findings[0].claim.derivation is Derivation.DESCRIPTION


def test_non_latin_description_paired_with_a_latin_name_is_not_reported() -> None:
    # The false positive this row exists to close: a legitimately non-English
    # description must never fire, regardless of script.
    for description in (
        "从工作区读取文件。",  # Chinese
        "Διαβάζει ένα αρχείο από τον χώρο εργασίας.",  # Greek
        "قراءة ملف من مساحة العمل.",  # Arabic
        "Читает файл из рабочей области.",  # Cyrillic
    ):
        assert CHECK.run(_context(description)) == [], description


def test_confusable_name_mixing_cyrillic_and_latin_is_reported() -> None:
    # Cyrillic 'е' (U+0435) inside an otherwise Latin identifier
    findings = CHECK.run(_context("Reads a file.", name="rеad_file"))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].claim.derivation is Derivation.NAME


def test_genuinely_non_latin_tool_name_is_not_a_confusable_finding() -> None:
    # A tool name written entirely in another script has no Latin letters to
    # be confused with — it is not the spoofing shape.
    assert CHECK.run(_context("Reads a file.", name="读取文件")) == []
