from datetime import UTC, date, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.registry import SkipReason, applicable
from agent_perimeter.checks.revision.header_body_mismatch import CHECK
from agent_perimeter.model.feature import Revision
from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.revision import Fingerprint


class RecordingTransport:
    """Answers the mismatched probe according to `honours_body`."""

    def __init__(self, *, honours_body: bool) -> None:
        self.honours_body = honours_body
        self.sent: list[tuple[str, dict[str, object] | None]] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.sent.append((method, params))
        if params and params.get("_ap_header_override"):
            if self.honours_body:
                return {"resultType": "complete", "content": []}
            msg = "HeaderMismatchError (-32020)"
            raise TransportError(msg)
        return {"resultType": "complete", "tools": []}

    def close(self) -> None: ...


def _context(transport: RecordingTransport) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test/rpc",
        transport=transport,
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
    )


def test_server_honouring_the_body_is_reported() -> None:
    findings = CHECK.run(_context(RecordingTransport(honours_body=True)))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-346"
    assert findings[0].severity is Severity.HIGH


def test_server_rejecting_the_mismatch_is_clean() -> None:
    assert CHECK.run(_context(RecordingTransport(honours_body=False))) == []


def test_check_requires_authorisation() -> None:
    assert CHECK.requires_auth is True


def test_probe_is_sent_exactly_once() -> None:
    transport = RecordingTransport(honours_body=False)
    CHECK.run(_context(transport))
    assert len(transport.sent) == 1


def test_finding_records_a_probe_derived_claim() -> None:
    finding = CHECK.run(_context(RecordingTransport(honours_body=True)))[0]
    assert finding.claim.derivation is Derivation.PROBE


def test_check_is_skipped_without_a_scope_file_end_to_end() -> None:
    """The only `revision/` check with `requires_auth = True` — hard constraint
    1 requires proof that the real singleton, not a stand-in, is refused by the
    registry when no scope file is supplied."""
    runnable, skipped = applicable(
        [CHECK],
        frozenset(),
        scope=None,
        target="https://mcp.example.test/rpc",
        today=date(2026, 9, 1),
    )
    assert runnable == []
    assert skipped[0].check_id == CHECK.id
    assert skipped[0].reason is SkipReason.NOT_AUTHORISED


class ForwardingTransport(RecordingTransport):
    """The pre-fix behaviour of every non-Streamable-HTTP transport: it does
    not understand `_ap_header_override`, so it forwards it as an ordinary
    JSON-RPC param and a tolerant server answers `tools/list` normally. If
    the check ever reads that as "the mismatched body was honoured" it emits
    a HIGH-severity false positive on every stdio and legacy-SSE target."""

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        self.sent.append((method, params))
        return {"resultType": "complete", "tools": []}


def test_a_transport_that_cannot_diverge_header_from_body_is_not_reported() -> None:
    """Fails closed: "could not probe" must never render as "probed clean",
    and certainly never as a finding. Driven through the real StdioTransport
    guard — constructed without __init__ because the guard runs before the
    transport touches its pipes, so no container is needed."""
    from agent_perimeter.transport.stdio import StdioTransport

    assert CHECK.run(_context(object.__new__(StdioTransport))) == []  # type: ignore[arg-type]


def test_a_transport_that_silently_forwards_the_probe_would_false_positive() -> None:
    """Guards the guard: this is what the check does when a transport answers
    normally, which is exactly why the refusal has to live in the transport."""
    assert len(CHECK.run(_context(ForwardingTransport(honours_body=False)))) == 1
