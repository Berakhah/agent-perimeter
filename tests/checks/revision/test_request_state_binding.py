import base64
import json
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.revision.request_state_binding import CHECK
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint


class NullTransport:
    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        return {}

    def close(self) -> None: ...


def _context(request_state: object) -> ScanContext:
    return ScanContext(
        target="https://mcp.example.test",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.MRTR}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw={
            "tools/call": {
                "resultType": "input_required",
                "requestState": request_state,
                "inputRequests": [],
            }
        },
    )


def _plain(payload: dict[str, object]) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def test_transparent_request_state_is_reported_at_medium_as_an_observation() -> None:
    findings = CHECK.run(_context(_plain({"user": "alice", "step": 2})))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-200"
    assert findings[0].severity is Severity.MEDIUM
    assert "transparent" in findings[0].title.lower()
    assert "no integrity protection" not in findings[0].title.lower()


def test_raw_json_request_state_is_reported() -> None:
    assert len(CHECK.run(_context('{"user":"alice"}'))) == 1


def test_signed_request_state_is_clean() -> None:
    signed = f"{_plain({'user': 'alice'})}.{_plain({'exp': 1})}.c2lnbmF0dXJl"
    assert CHECK.run(_context(signed)) == []


def test_opaque_request_state_is_clean() -> None:
    assert CHECK.run(_context("dGhpcyBpcyBub3QgSlNPTiBhdCBhbGw")) == []


def test_no_input_required_result_means_nothing_to_check() -> None:
    context = ScanContext(
        target="t",
        transport=NullTransport(),
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            features=frozenset({Feature.MRTR}),
            claim=Claim(
                value="2026-07-28",
                method=Method.DETERMINISTIC,
                derivation=Derivation.PROBE,
                observed_at=datetime.now(UTC),
            ),
        ),
        raw={"tools/list": {"resultType": "complete", "tools": []}},
    )
    assert CHECK.run(context) == []
