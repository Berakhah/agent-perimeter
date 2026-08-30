# agent_perimeter/checks/all_checks.py
"""The registered check set.

Order is display order. Adding a check here is what makes it run, and the
suite asserts every entry cites a resolvable taxonomy entry — so an uncited
check cannot be registered.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_perimeter.checks.base import Check
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.descriptions import (
    imperative_injection,
    name_schema_mismatch,
    shadowing,
    unicode_anomaly,
)
from agent_perimeter.checks.descriptions.llm_judge import LlmJudgeCheck, Verdict
from agent_perimeter.checks.revision import (
    cache_scope,
    conformance_mismatch,
    deprecated_features,
    header_annotation_invalid,
    header_annotation_type,
    header_annotation_unreachable,
    header_body_mismatch,
    issuer_validation,
    registration_mode,
    request_state_binding,
    schema_composition,
    state_handle_exposure,
)
from agent_perimeter.checks.secrets import config_scan, env_scan, history_scan
from agent_perimeter.checks.static import (
    auth_mode,
    cleartext_target,
    scope_breadth,
    session_state,
    token_passthrough,
)
from agent_perimeter.model.finding import Finding


class UnavailableJudge:
    """Placeholder gateway used until bok-core's gateway is wired in.

    ponytail: returns UNDETERMINED for everything, so the judge check registers
    and is counted, but asserts nothing. Replace with the bok-core gateway when
    it publishes; the registry already skips this check as MODEL_UNAVAILABLE
    when no provider is reachable.
    """

    def classify(self, content: str, schema: type[Verdict]) -> Verdict:
        return Verdict.UNDETERMINED


ALL_CHECKS: tuple[Check, ...] = (
    # revision — 12
    cache_scope.CHECK,
    header_annotation_invalid.CHECK,
    header_annotation_unreachable.CHECK,
    header_annotation_type.CHECK,
    schema_composition.CHECK,
    state_handle_exposure.CHECK,
    request_state_binding.CHECK,
    deprecated_features.CHECK,
    conformance_mismatch.CHECK,
    registration_mode.CHECK,
    issuer_validation.CHECK,
    header_body_mismatch.CHECK,
    # static — 5
    auth_mode.CHECK,
    cleartext_target.CHECK,
    token_passthrough.CHECK,
    session_state.CHECK,
    scope_breadth.CHECK,
    # descriptions — 5
    unicode_anomaly.CHECK,
    imperative_injection.CHECK,
    name_schema_mismatch.CHECK,
    shadowing.CHECK,
    LlmJudgeCheck(UnavailableJudge()),
    # secrets — 3
    config_scan.CHECK,
    env_scan.CHECK,
    history_scan.CHECK,
)


@dataclass(frozen=True)
class CheckOutcome:
    """What happened to one check that did not simply return findings."""

    check_id: str
    status: str  # "errored"
    reason: str


def run_checks(
    runnable: list[Check], context: ScanContext
) -> tuple[list[Finding], list[CheckOutcome]]:
    """Run every check, isolating a raising one from the rest of the scan.

    A check that raises is exactly as informative as one that finds nothing —
    less, if its failure is silent — so it is recorded, not swallowed.
    """
    findings: list[Finding] = []
    errored: list[CheckOutcome] = []
    for check in runnable:
        try:
            findings.extend(check.run(context))
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any check may raise
            errored.append(
                CheckOutcome(
                    check_id=check.id, status="errored", reason=f"{type(exc).__name__}: {exc}"
                )
            )
    return findings, errored


def summarise_errors(errored: list[CheckOutcome]) -> str:
    if not errored:
        return ""
    names = ", ".join(f"{o.check_id} ({o.reason})" for o in errored)
    return f"{len(errored)} check(s) errored and were skipped for this run: {names}."
