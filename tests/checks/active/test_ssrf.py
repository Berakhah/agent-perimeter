from datetime import UTC, date, datetime

from agent_perimeter._contracts import Claim, Derivation, Method, Severity
from agent_perimeter.checks.active.ssrf import CHECK
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.discover.enumerate import ToolRecord
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


class ProbeTransport:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.urls: list[str] = []

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method != "tools/call":
            return {}
        arguments = (params or {}).get("arguments")
        if isinstance(arguments, dict):
            self.urls.append(str(arguments.get("url", "")))
        return {"content": [{"type": "text", "text": self.reply}]}

    def close(self) -> None: ...


def _context(transport: ProbeTransport) -> ScanContext:
    return ScanContext(
        target=TARGET,
        transport=transport,
        fingerprint=Fingerprint(
            revision_claimed=Revision.R2026_07_28,
            # Correction (task-3 brief, same as task-21/22): Feature.STATELESS_META
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
        tools=[
            ToolRecord(
                name="fetch",
                description="Fetch a URL.",
                input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            )
        ],
        scope=SCOPE,
    )


def test_connection_attempt_is_reported() -> None:
    findings = CHECK.run(_context(ProbeTransport("Connection refused to 127.0.0.1:9")))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-918"
    assert findings[0].severity is Severity.INFO


def test_finding_states_what_it_does_not_prove() -> None:
    """No out-of-band channel confirms the attempt -- the finding must say
    so rather than claiming a confirmation it does not have (revision §8)."""
    finding = CHECK.run(_context(ProbeTransport("Connection refused to 127.0.0.1:9")))[0]
    assert "does not confirm" in finding.evidence.excerpt.lower()
    assert finding.claim.caveat is not None


def test_timeout_also_counts_as_an_attempt() -> None:
    assert CHECK.run(_context(ProbeTransport("Timed out connecting to host")))


def test_policy_refusal_is_clean() -> None:
    reply = "Refused: destination host is not in the allowlist."
    assert CHECK.run(_context(ProbeTransport(reply))) == []


def test_probe_targets_only_the_discard_port_canary() -> None:
    transport = ProbeTransport("Connection refused")
    CHECK.run(_context(transport))
    for url in transport.urls:
        assert "127.0.0.1:9" in url
        assert "169.254.169.254" not in url
        assert "metadata" not in url


def test_check_requires_authorisation() -> None:
    assert CHECK.requires_auth is True
