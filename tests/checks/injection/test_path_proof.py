from datetime import UTC, date, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.injection.path_proof import CHECK, find_paths
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.graph.build import build_graph
from agent_perimeter.model.feature import Revision
from agent_perimeter.model.scope import ScopeFile
from agent_perimeter.transport.revision import Fingerprint

TARGET = "https://mcp.example.test/rpc"
SCOPE = ScopeFile(
    target=TARGET,
    authorising_party="Example Ltd",
    authorised_on=date(2026, 8, 30),
    attestation="I authorise active probing.",
)

SOURCE = ToolRecord(
    name="fetch_page",
    description="Fetch a web page.",
    input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
)
SINK = ToolRecord(
    name="run_command",
    description="Run a command.",
    input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
)
HARMLESS = ToolRecord(
    name="add",
    description="Add two numbers.",
    input_schema={"type": "object", "properties": {"a": {"type": "number"}}},
)


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {"content": [{"type": "text", "text": "ok"}]}

    def close(self) -> None: ...


def _context(*tools: ToolRecord, scope: ScopeFile | None = SCOPE) -> ScanContext:
    return ScanContext(
        target=TARGET,
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-7 brief, same as task-3/4/5/6): Feature.STATELESS_META
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
        tools=list(tools),
        scope=scope,
    )


def test_source_to_sink_path_is_found() -> None:
    paths = find_paths(build_graph([SOURCE, SINK]))
    assert ("fetch_page", "run_command") in paths


def test_no_sink_means_no_path() -> None:
    assert find_paths(build_graph([SOURCE, HARMLESS])) == []


def test_no_source_means_no_path() -> None:
    assert find_paths(build_graph([SINK, HARMLESS])) == []


def test_path_is_reported_as_high_without_canary_confirmation() -> None:
    findings = CHECK.run(_context(SOURCE, SINK))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].cwe == "CWE-1427"
    # SOURCE's "url" and SINK's "command" are both name-regex matches (Task
    # 1), not structural schema evidence, so the weakest-derivation claim is
    # Derivation.NAME here -- not the SCHEMA the pre-Task-1 graph reported.
    assert findings[0].claim.derivation is Derivation.NAME


def test_finding_names_both_ends_of_the_path() -> None:
    finding = CHECK.run(_context(SOURCE, SINK))[0]
    assert "fetch_page" in finding.title
    assert "run_command" in finding.title


def test_check_is_deterministic_and_needs_no_model() -> None:
    assert CHECK.requires_model is False


def test_clean_tool_set_reports_nothing() -> None:
    assert CHECK.run(_context(HARMLESS)) == []
