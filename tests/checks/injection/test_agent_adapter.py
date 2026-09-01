import json
from datetime import UTC, datetime
from pathlib import Path

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.injection.agent_adapter import (
    CHECK,
    INSTRUMENTED_MARKER,
    load_transcript,
)
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(transcript: dict[str, object] | None) -> ScanContext:
    raw: dict[str, dict[str, object]] = {}
    if transcript is not None:
        raw["_agent_transcript"] = transcript
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-8 brief, same as task-3..7): Feature.STATELESS_META
            # does not exist -- a version-implies-feature proxy this design
            # deliberately avoids (see agent_perimeter/model/feature.py). No
            # feature is needed for these tests, so the fixture asserts none.
            features=frozenset(),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw=raw,
    )


BIT = {
    "tool_calls": [
        {"name": "fetch_page", "result": f"...{INSTRUMENTED_MARKER}..."},
        {"name": "run_command", "arguments": {"command": "whoami"}},
    ]
}
DECLINED = {"tool_calls": [{"name": "fetch_page", "result": f"...{INSTRUMENTED_MARKER}..."}]}


def test_agent_that_took_the_bait_is_reported() -> None:
    findings = CHECK.run(_context(BIT))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cwe == "CWE-1427"
    assert "run_command" in findings[0].evidence.excerpt


def test_agent_that_declined_is_clean() -> None:
    assert CHECK.run(_context(DECLINED)) == []


def test_no_transcript_reports_nothing_rather_than_clean() -> None:
    assert CHECK.run(_context(None)) == []


def test_check_calls_no_model() -> None:
    assert CHECK.requires_model is False


def test_transcript_loads_from_disk(tmp_path: Path) -> None:
    path = tmp_path / "transcript.json"
    path.write_text(json.dumps(BIT))
    transcript = load_transcript(path)
    assert transcript.took_bait is True
    assert transcript.marker_seen is True


def test_transcript_without_marker_is_not_a_bait_case(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"tool_calls": [{"name": "run_command"}]}))
    assert load_transcript(path).marker_seen is False
