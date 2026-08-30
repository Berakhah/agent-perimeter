from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.state_handle_exposure import CHECK
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(properties: dict[str, object]) -> ScanContext:
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
        tools=[
            ToolRecord(
                name="continue_job",
                description="Continue a job.",
                input_schema={"type": "object", "properties": properties},
            )
        ],
    )


def test_unmarked_session_handle_parameter_is_reported() -> None:
    findings = CHECK.run(_context({"sessionHandle": {"type": "string"}}))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-200"
    assert findings[0].severity is Severity.MEDIUM
    assert "sessionHandle" in findings[0].title


def test_various_handle_names_are_recognised() -> None:
    for name in ("session_token", "stateHandle", "continuationToken", "job_handle"):
        assert CHECK.run(_context({name: {"type": "string"}})), name


def test_handle_with_an_opaque_format_is_clean() -> None:
    assert CHECK.run(_context({"sessionHandle": {"type": "string", "format": "opaque"}})) == []


def test_handle_with_a_pattern_is_clean() -> None:
    schema = {"sessionHandle": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}}
    assert CHECK.run(_context(schema)) == []


def test_ordinary_parameter_is_clean() -> None:
    assert CHECK.run(_context({"path": {"type": "string"}})) == []


def test_standard_pagination_cursor_is_not_reported() -> None:
    assert CHECK.run(_context({"cursor_id": {"type": "string"}})) == []
    assert CHECK.run(_context({"cursor": {"type": "string"}})) == []


def test_standard_tasks_handle_is_not_reported() -> None:
    assert CHECK.run(_context({"task_id": {"type": "string"}})) == []


def test_max_length_alone_no_longer_counts_as_opaque() -> None:
    schema = {"sessionHandle": {"type": "string", "maxLength": 64}}
    assert CHECK.run(_context(schema)) != []


def test_finding_uses_name_derivation_with_reduced_confidence() -> None:
    finding = CHECK.run(_context({"sessionHandle": {"type": "string"}}))[0]
    assert finding.claim.derivation is Derivation.NAME
    assert finding.confidence is not None and finding.confidence < 1.0
