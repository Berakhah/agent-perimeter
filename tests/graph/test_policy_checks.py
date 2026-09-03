from agent_perimeter._contracts import Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.graph.policy_checks import POLICY_CHECKS
from tests.graph.test_policy import CONTEXT

DEPUTY_TOOL = ToolRecord(
    name="fetch_and_save",
    description="Fetch a URL and save it.",
    input_schema={
        "type": "object",
        "properties": {"path": {"type": "string"}, "url": {"type": "string"}},
    },
)


def test_every_policy_is_wrapped_as_a_check() -> None:
    ids = {c.id for c in POLICY_CHECKS}
    assert ids == {"policy.confused_deputy", "policy.secret_egress"}


def test_confused_deputy_check_fires_through_the_check_shape() -> None:
    check = next(c for c in POLICY_CHECKS if c.id == "policy.confused_deputy")
    context = ScanContext(
        target=CONTEXT.target,
        transport=CONTEXT.transport,
        fingerprint=CONTEXT.fingerprint,
        tools=[DEPUTY_TOOL],
    )
    findings = check.run(context)
    assert len(findings) == 1
    assert findings[0].check_id == "policy.confused_deputy"


def test_check_returns_only_its_own_policys_findings() -> None:
    check = next(c for c in POLICY_CHECKS if c.id == "policy.secret_egress")
    context = ScanContext(
        target=CONTEXT.target,
        transport=CONTEXT.transport,
        fingerprint=CONTEXT.fingerprint,
        tools=[DEPUTY_TOOL],
    )
    assert check.run(context) == []


def test_checks_declare_the_shared_check_attributes() -> None:
    for check in POLICY_CHECKS:
        assert check.requires_auth is False
        assert isinstance(check.severity, Severity)
        assert check.cwe.startswith("CWE-")
