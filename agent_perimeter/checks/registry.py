"""Decide which checks apply, and record why the others did not.

A skipped check is never silently absent. The report states the count skipped
and the reason, because a security tool that quietly degrades is worse than one
that was never installed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from agent_perimeter.checks.base import Check
from agent_perimeter.model.feature import FeatureSet
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope


class SkipReason(StrEnum):
    FEATURE_ABSENT = "feature_absent"
    NOT_AUTHORISED = "not_authorised"
    MODEL_UNAVAILABLE = "model_unavailable"
    NO_BASELINE = "no_baseline"


class BaselineStatus(StrEnum):
    """Why a baseline-requiring check may not have one. Two absent states,
    two messages: "no baseline" when the truth is "database down" is lying
    by omission."""

    PRESENT = "present"
    NONE_ON_RECORD = "none_on_record"
    SOURCE_UNAVAILABLE = "source_unavailable"


_NO_BASELINE_DETAIL: dict[BaselineStatus, str] = {
    BaselineStatus.NONE_ON_RECORD: (
        "no earlier scan of this target to compare against — pass --baseline (CLI) "
        "or scan this target again (API)"
    ),
    BaselineStatus.SOURCE_UNAVAILABLE: (
        "the scan database was unreachable, so no baseline could be loaded"
    ),
}


@dataclass(frozen=True)
class Skipped:
    check_id: str
    reason: SkipReason
    detail: str


def applicable(
    checks: Iterable[Check],
    features: FeatureSet,
    *,
    scope: ScopeFile | None,
    target: str,
    today: date,
    models_available: bool = True,
    baseline_status: BaselineStatus = BaselineStatus.NONE_ON_RECORD,
) -> tuple[list[Check], list[Skipped]]:
    runnable: list[Check] = []
    skipped: list[Skipped] = []

    for check in checks:
        missing = check.requires_features - features
        if missing:
            names = ", ".join(sorted(feature.value for feature in missing))
            skipped.append(Skipped(check.id, SkipReason.FEATURE_ABSENT, f"target lacks: {names}"))
            continue

        if check.requires_model and not models_available:
            skipped.append(
                Skipped(check.id, SkipReason.MODEL_UNAVAILABLE, "no model provider is reachable")
            )
            continue

        if check.requires_baseline and baseline_status is not BaselineStatus.PRESENT:
            skipped.append(
                Skipped(check.id, SkipReason.NO_BASELINE, _NO_BASELINE_DETAIL[baseline_status])
            )
            continue

        if check.requires_auth:
            try:
                require_scope(scope, check_id=check.id, target=target, today=today)
            except AuthorizationRequired as exc:
                skipped.append(Skipped(check.id, SkipReason.NOT_AUTHORISED, str(exc)))
                continue

        runnable.append(check)

    return runnable, skipped


def summarise_skips(skipped: Sequence[Skipped]) -> str:
    """Render the skip summary that the report and the CLI both print."""
    if not skipped:
        return "No checks were skipped."
    by_reason: dict[SkipReason, int] = {}
    for item in skipped:
        by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
    parts = ", ".join(f"{count} {reason.value}" for reason, count in sorted(by_reason.items()))
    return f"{len(skipped)} checks skipped ({parts})."
