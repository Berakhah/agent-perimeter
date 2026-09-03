# agent_perimeter/checks/all_checks.py
"""The registered check set.

Order is display order. Adding a check here is what makes it run, and the
suite asserts every entry cites a resolvable taxonomy entry — so an uncited
check cannot be registered.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace

from agent_perimeter.checks.active import (
    command_injection,
    confused_deputy,
    path_traversal,
    ssrf,
)
from agent_perimeter.checks.base import Check
from agent_perimeter.checks.context import ScanContext, _UnauthorisedTransport
from agent_perimeter.checks.descriptions import (
    imperative_injection,
    name_schema_mismatch,
    shadowing,
    unicode_anomaly,
)
from agent_perimeter.checks.descriptions.llm_judge import LlmJudgeCheck, Verdict
from agent_perimeter.checks.injection import agent_adapter, path_proof
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
from agent_perimeter.graph.policy_checks import POLICY_CHECKS
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
    # active — 4 (all scope-gated)
    path_traversal.CHECK,
    ssrf.CHECK,
    command_injection.CHECK,
    confused_deputy.CHECK,
    # injection — 2
    path_proof.CHECK,
    agent_adapter.CHECK,
    # policy — 2 (registered checks now, not a bolted-on evaluate() call)
    *POLICY_CHECKS,
)


@dataclass(frozen=True)
class CheckOutcome:
    """What happened to one check that did not simply return findings."""

    check_id: str
    status: str  # "errored"
    reason: str


def run_checks(
    runnable: list[Check],
    context: ScanContext,
    *,
    on_check: Callable[[Check, str, float], None] | None = None,
) -> tuple[list[Finding], list[CheckOutcome]]:
    """Run every check, isolating a raising one from the rest of the scan.

    A check that raises is exactly as informative as one that finds nothing —
    less, if its failure is silent — so it is recorded, not swallowed.

    `on_check`, if given, is called once per check after it completes, with
    its id's status ("passed" or "errored") and real elapsed time in
    milliseconds — Task 9's SSE progress stream is built on this, without
    this module (or the security-relevant transport-wrapping boundary below)
    knowing anything about HTTP or FastAPI.
    """
    findings: list[Finding] = []
    errored: list[CheckOutcome] = []
    for check in runnable:
        # A check's own `requires_auth` flag is self-reported; applicable()
        # trusts it to filter the runnable list, but nothing stops a check's
        # `run()` body from calling the transport directly. Wrapping the
        # transport here enforces the boundary structurally instead of by
        # convention, for every check regardless of what its own code does.
        check_context = (
            context
            if check.requires_auth
            else replace(context, transport=_UnauthorisedTransport(context.transport))
        )
        start = time.monotonic()
        try:
            findings.extend(check.run(check_context))
            status = "passed"
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any check may raise
            errored.append(
                CheckOutcome(
                    check_id=check.id, status="errored", reason=f"{type(exc).__name__}: {exc}"
                )
            )
            status = "errored"
        if on_check is not None:
            on_check(check, status, (time.monotonic() - start) * 1000)
    return findings, errored


def summarise_errors(errored: list[CheckOutcome]) -> str:
    if not errored:
        return ""
    names = ", ".join(f"{o.check_id} ({o.reason})" for o in errored)
    return f"{len(errored)} check(s) errored and were skipped for this run: {names}."
