from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.schema_composition import CHECK
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(schema: dict[str, object]) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test",
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
        tools=[ToolRecord(name="t", description="", input_schema=schema)],
    )


def test_external_ref_is_reported() -> None:
    findings = CHECK.run(
        _context({"$ref": "https://attacker.example.test/schema.json"})
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "attacker.example.test" in findings[0].evidence.excerpt


def test_nested_external_ref_is_found() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"items": {"$ref": "http://evil.example.test/s.json"}}},
    }
    assert len(CHECK.run(_context(schema))) == 1


def test_self_referential_ref_chain_is_reported() -> None:
    schema = {
        "type": "object",
        "$defs": {"node": {"properties": {"child": {"$ref": "#/$defs/node"}}}},
        "properties": {"root": {"$ref": "#/$defs/node"}},
    }
    findings = CHECK.run(_context(schema))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-674"


def test_local_non_recursive_ref_is_clean() -> None:
    schema = {
        "type": "object",
        "$defs": {"name": {"type": "string"}},
        "properties": {"n": {"$ref": "#/$defs/name"}},
    }
    assert CHECK.run(_context(schema)) == []


def test_plain_schema_is_clean() -> None:
    assert CHECK.run(_context({"type": "object", "properties": {"p": {"type": "string"}}})) == []


def test_metadata_address_ref_is_critical_not_high() -> None:
    findings = CHECK.run(_context({"$ref": "http://169.254.169.254/latest/meta-data/"}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_uppercase_scheme_external_ref_is_not_missed() -> None:
    findings = CHECK.run(_context({"$ref": "HTTPS://attacker.example.test/s.json"}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


def test_file_scheme_ref_is_reported() -> None:
    assert len(CHECK.run(_context({"$ref": "file:///etc/passwd"}))) == 1


def test_a_thousand_deep_nested_schema_does_not_raise_and_produces_a_bound_finding() -> None:
    schema: dict[str, object] = {"type": "object"}
    node = schema
    for _ in range(1000):
        child: dict[str, object] = {"type": "object", "properties": {}}
        node["properties"] = {"nested": child}  # type: ignore[assignment]
        node = child

    findings = CHECK.run(_context(schema))  # must not raise RecursionError
    assert any("depth" in f.title.lower() or "bound" in f.title.lower() for f in findings)


def test_collect_refs_is_iterative_not_recursive() -> None:
    import inspect

    from agent_perimeter.checks.revision.schema_composition import _collect_refs

    source = inspect.getsource(_collect_refs)
    assert "_collect_refs(" not in source.split("def _collect_refs", 1)[1], (
        "_collect_refs must not call itself — use an explicit stack"
    )
