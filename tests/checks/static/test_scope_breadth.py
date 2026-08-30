from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.static.scope_breadth import CHECK
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(
    metadata: dict[str, object] | None = None, tools: list[ToolRecord] | None = None
) -> ScanContext:
    raw: dict[str, dict[str, object]] = {}
    if metadata is not None:
        raw["oauth/metadata"] = metadata
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
        tools=tools or [],
        raw=raw,
    )


def test_wildcard_scope_is_reported() -> None:
    findings = CHECK.run(_context({"scopes_supported": ["*"]}))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-250"
    assert findings[0].severity is Severity.MEDIUM


def test_admin_scope_is_reported() -> None:
    assert len(CHECK.run(_context({"scopes_supported": ["admin"]}))) == 1


def test_narrow_scopes_are_clean() -> None:
    assert CHECK.run(_context({"scopes_supported": ["files.read", "files.write"]})) == []


def test_read_only_hint_contradicted_by_name_and_description_is_reported() -> None:
    tool = ToolRecord(
        name="delete_record",
        description="Deletes a record from the database.",
        annotations={"readOnlyHint": True},
    )
    findings = CHECK.run(_context(tools=[tool]))
    assert len(findings) == 1
    assert "readOnlyHint" in findings[0].title


def test_name_prefix_alone_with_no_corroborating_description_is_not_reported() -> None:
    # run_query and post_process are ordinary read-only operations whose
    # names happen to start with a verb the old regex treated as mutating.
    tool = ToolRecord(
        name="run_query",
        description="Runs a read-only analytics query and returns the rows.",
        annotations={"readOnlyHint": True},
    )
    assert CHECK.run(_context(tools=[tool])) == []


def test_consistent_read_only_tool_is_clean() -> None:
    tool = ToolRecord(
        name="get_record", description="Read a record.", annotations={"readOnlyHint": True}
    )
    assert CHECK.run(_context(tools=[tool])) == []


def test_annotation_finding_uses_name_derivation() -> None:
    tool = ToolRecord(
        name="delete_record",
        description="Deletes a record from the database.",
        annotations={"readOnlyHint": True},
    )
    finding = CHECK.run(_context(tools=[tool]))[0]
    assert finding.claim.derivation is Derivation.NAME
    assert finding.confidence is not None and finding.confidence < 1.0
