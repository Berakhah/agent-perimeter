from datetime import UTC, date, datetime

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.scope import ScopeFile
from agent_perimeter.transport.revision import Fingerprint


class FakeTransport:
    """Minimal Transport implementation for testing."""

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    def close(self) -> None:
        pass


def test_scan_context_construction_with_required_fields_only() -> None:
    """ScanContext can be constructed with only required fields, defaults work correctly."""
    transport = FakeTransport()
    fingerprint = Fingerprint(
        revision_claimed=Revision.R2026_07_28,
        features=frozenset({Feature.SERVER_DISCOVER}),
        claim=Claim(
            value="2026-07-28",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )
    target = "stdio://path/to/server"

    context = ScanContext(
        target=target,
        transport=transport,
        fingerprint=fingerprint,
    )

    assert context.target == target
    assert context.transport is transport
    assert context.fingerprint is fingerprint
    assert context.tools == []
    assert context.raw == {}
    assert context.scope is None
    assert context.ambiguous_tools == frozenset()


def test_scan_context_reproduction_formats_command_correctly() -> None:
    """reproduction(check_id) returns the expected command format."""
    transport = FakeTransport()
    fingerprint = Fingerprint(
        revision_claimed=Revision.R2026_07_28,
        features=frozenset(),
        claim=Claim(
            value="2026-07-28",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )
    target = "stdio://path/to/server"
    context = ScanContext(target=target, transport=transport, fingerprint=fingerprint)

    reproduction_cmd = context.reproduction("revision.version_claimed")
    assert reproduction_cmd == "agent-perimeter scan --target stdio://path/to/server --only revision.version_claimed"


def test_scan_context_construction_with_all_fields_populated() -> None:
    """ScanContext accepts and stores all fields correctly."""
    transport = FakeTransport()
    fingerprint = Fingerprint(
        revision_claimed=Revision.R2026_07_28,
        features=frozenset({Feature.SERVER_DISCOVER}),
        claim=Claim(
            value="2026-07-28",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )
    target = "https://example.test/mcp"
    tools = [
        ToolRecord(
            name="read_file",
            description="Read a file",
            input_schema={"type": "object"},
            annotations={"readOnlyHint": True},
        )
    ]
    raw = {
        "tools/list": {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    }
    scope = ScopeFile(
        target=target,
        authorising_party="Test Corp",
        authorised_on=date(2026, 8, 30),
        attestation="I authorise this scan.",
    )
    ambiguous = frozenset({"descriptions.llm_judge"})

    context = ScanContext(
        target=target,
        transport=transport,
        fingerprint=fingerprint,
        tools=tools,
        raw=raw,
        scope=scope,
        ambiguous_tools=ambiguous,
    )

    assert context.target == target
    assert context.transport is transport
    assert context.fingerprint is fingerprint
    assert context.tools == tools
    assert context.raw == raw
    assert context.scope is scope
    assert context.ambiguous_tools == ambiguous


def test_scan_context_is_frozen() -> None:
    """ScanContext is immutable after construction."""
    transport = FakeTransport()
    fingerprint = Fingerprint(
        revision_claimed=None,
        features=frozenset(),
        claim=Claim(
            value="unknown",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )
    context = ScanContext(target="test", transport=transport, fingerprint=fingerprint)

    try:
        context.target = "modified"  # type: ignore[misc]
        assert False, "Should have raised FrozenInstanceError"
    except AttributeError:
        pass


def test_scan_context_reproduction_with_special_characters_in_target() -> None:
    """reproduction() handles targets with special characters."""
    transport = FakeTransport()
    fingerprint = Fingerprint(
        revision_claimed=None,
        features=frozenset(),
        claim=Claim(
            value="unknown",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )
    target = "https://example.test:8080/path?query=1&other=2"
    context = ScanContext(target=target, transport=transport, fingerprint=fingerprint)

    reproduction_cmd = context.reproduction("active.ssrf")
    assert reproduction_cmd == f"agent-perimeter scan --target {target} --only active.ssrf"
