"""Degraded mode measured by findings actually produced, not by registrations.

len([c for c in ALL_CHECKS if not c.requires_model]) / len(ALL_CHECKS) is a
fixed ratio that cannot fail regardless of real behaviour. This runs the
fixture corpus twice -- providers enabled, then disabled -- and compares the
sets of check ids that actually fired. A metric that cannot fail is not a
metric (revision §4.5).
"""

from agent_perimeter.eval.corpus import load_corpus
from agent_perimeter.eval.harness import run_case


def _distinct_firing_check_ids(*, models_available: bool) -> set[str]:
    fired: set[str] = set()
    for case in load_corpus():
        fired |= run_case(case, models_available=models_available)
    return fired


def test_degraded_mode_still_produces_findings() -> None:
    enabled = _distinct_firing_check_ids(models_available=True)
    disabled = _distinct_firing_check_ids(models_available=False)
    assert enabled, "no check fired with providers enabled -- nothing to compare against"
    ratio = len(disabled) / len(enabled)
    assert ratio >= 0.90, (
        f"only {len(disabled)}/{len(enabled)} check classes still produced a "
        f"finding with providers disabled"
    )
