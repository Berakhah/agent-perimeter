from agent_perimeter.checks.all_checks import ALL_CHECKS


def test_degraded_mode_still_produces_findings() -> None:
    """With every model provider disabled, at least 90% of check classes survive.

    Higher than the shared-foundation floor of 70%, because a security tool
    that silently degrades is worse than one that was never installed.

    Revision 2026-08-29 section 4.5: this must count checks that actually
    *produce findings* against the fixture corpus, not merely checks that are
    *registered*, or the metric cannot fail. Week 3's eval harness (which runs
    the fixture corpus with providers on and off and diffs the emitting
    check_ids) is where that stronger version lands; this week's version is
    the honest interim — registrations only, and it says so.
    """
    total = len(ALL_CHECKS)
    surviving = [c for c in ALL_CHECKS if not c.requires_model]
    assert len(surviving) / total >= 0.90, (
        f"only {len(surviving)}/{total} check classes survive with models disabled"
    )
