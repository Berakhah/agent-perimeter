from dataclasses import dataclass
from datetime import date

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.registry import SkipReason, applicable, summarise_skips
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.finding import Finding
from agent_perimeter.model.scope import ScopeFile

TODAY = date(2026, 9, 1)
TARGET = "https://mcp.example.test"

SCOPE = ScopeFile(
    target=TARGET,
    authorising_party="Example Ltd",
    authorised_on=date(2026, 8, 30),
    attestation="I authorise active probing.",
)


@dataclass(frozen=True)
class FakeCheck:
    id: str
    requires_features: frozenset[Feature] = frozenset()
    requires_auth: bool = False
    requires_model: bool = False
    cwe: str = "CWE-000"
    severity: Severity = Severity.INFO
    taxonomy_refs: tuple[str, ...] = ()

    def run(self, context: ScanContext) -> list[Finding]:
        return []


MODERN = frozenset({Feature.SERVER_DISCOVER, Feature.CACHEABLE_RESULT})


def test_check_runs_when_its_features_are_present() -> None:
    check = FakeCheck("revision.cache_scope", frozenset({Feature.CACHEABLE_RESULT}))
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == [check]
    assert skipped == []


def test_check_is_skipped_with_a_reason_when_features_are_absent() -> None:
    check = FakeCheck("revision.mrtr", frozenset({Feature.MRTR}))
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == []
    assert skipped[0].check_id == "revision.mrtr"
    assert skipped[0].reason is SkipReason.FEATURE_ABSENT
    assert "mrtr" in skipped[0].detail


def test_active_check_is_skipped_without_a_scope_file() -> None:
    check = FakeCheck("active.ssrf", requires_auth=True)
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == []
    assert skipped[0].reason is SkipReason.NOT_AUTHORISED


def test_active_check_runs_with_a_valid_scope_file() -> None:
    check = FakeCheck("active.ssrf", requires_auth=True)
    runnable, skipped = applicable([check], MODERN, scope=SCOPE, target=TARGET, today=TODAY)
    assert runnable == [check]
    assert skipped == []


def test_model_check_is_skipped_when_no_provider_is_reachable() -> None:
    check = FakeCheck("descriptions.llm_judge", requires_model=True)
    runnable, skipped = applicable(
        [check], MODERN, scope=None, target=TARGET, today=TODAY, models_available=False
    )
    assert runnable == []
    assert skipped[0].reason is SkipReason.MODEL_UNAVAILABLE


def test_no_check_is_ever_silently_dropped() -> None:
    checks = [
        FakeCheck("a"),
        FakeCheck("b", frozenset({Feature.MRTR})),
        FakeCheck("c", requires_auth=True),
    ]
    runnable, skipped = applicable(checks, MODERN, scope=None, target=TARGET, today=TODAY)
    assert len(runnable) + len(skipped) == len(checks)
    assert "2 checks skipped" in summarise_skips(skipped)
