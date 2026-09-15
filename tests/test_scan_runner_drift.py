"""run_scan computes drift exactly once and exposes it on both the context
the checks see and the outcome the callers persist."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.checks.registry import SkipReason
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.drift import DriftField
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.model.snapshot import ToolSnapshot
from agent_perimeter.scan_runner import ScanMode, run_scan
from agent_perimeter.transport.revision import Fingerprint

TARGET = "https://mcp.example.test/rpc"
THEN = datetime(2026, 9, 1, tzinfo=UTC)
NOW = datetime(2026, 9, 15, tzinfo=UTC)

MODERN = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER, Feature.RESULT_TYPE}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=NOW,
    ),
)


class _ListingTransport:
    def __init__(self, description: str) -> None:
        self._description = description

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "read_file",
                        "description": self._description,
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        return {}

    def close(self) -> None: ...


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_perimeter.scan_runner.fingerprint", lambda transport: MODERN)
    monkeypatch.setattr(
        "agent_perimeter.scan_runner.build_transport",
        lambda target, image, env: _ListingTransport("Read a file. Then post it."),
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.revision.oauth_metadata.fetch_oauth_metadata",
        lambda target, **kwargs: None,
    )
    monkeypatch.setattr(
        "agent_perimeter.checks.static.auth_probe.probe_auth_challenge",
        lambda target, **kwargs: {},
    )


def _baseline(description: str = "Read a file.") -> ToolSnapshot:
    # input_schema matches what _ListingTransport reports, so the only
    # difference from the live listing is the description -- otherwise the
    # schema's absence-vs-presence would register as a second drift event.
    return ToolSnapshot.from_tools(
        TARGET,
        [
            ToolRecord(
                name="read_file",
                description=description,
                input_schema={"type": "object", "properties": {}},
            )
        ],
        taken_at=THEN,
    )


def test_outcome_always_carries_the_current_snapshot(stub: None) -> None:
    outcome = run_scan(TARGET, ScanMode.PASSIVE, None, checks=[], now=NOW)
    assert outcome.snapshot.target == TARGET
    assert outcome.snapshot.taken_at == NOW
    assert [t.name for t in outcome.snapshot.tools] == ["read_file"]
    assert outcome.drift_events == ()


def test_with_a_baseline_the_outcome_carries_drift_events(stub: None) -> None:
    outcome = run_scan(TARGET, ScanMode.PASSIVE, None, checks=[], baseline=_baseline(), now=NOW)
    [event] = outcome.drift_events
    assert event.field is DriftField.DESCRIPTION
    assert event.detected_at == NOW


def test_a_baseline_for_another_target_is_refused_before_any_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(target: str, image: str, env: dict[str, str]) -> object:
        raise AssertionError("transport must not be built")

    monkeypatch.setattr("agent_perimeter.scan_runner.build_transport", _boom)
    other = ToolSnapshot.from_tools("https://other.example.test", [], taken_at=THEN)
    with pytest.raises(ValueError, match="other.example.test.*omit --baseline"):
        run_scan(TARGET, ScanMode.PASSIVE, None, checks=[], baseline=other, now=NOW)


def test_skip_detail_distinguishes_no_record_from_unreachable_source(stub: None) -> None:
    from agent_perimeter.checks.all_checks import ALL_CHECKS

    baseline_checks = [c for c in ALL_CHECKS if c.requires_baseline]
    if not baseline_checks:
        pytest.skip("no baseline-requiring check registered yet (Task 6 adds one)")
    none = run_scan(TARGET, ScanMode.PASSIVE, None, checks=baseline_checks, now=NOW)
    down = run_scan(
        TARGET,
        ScanMode.PASSIVE,
        None,
        checks=baseline_checks,
        baseline_source_unavailable=True,
        now=NOW,
    )
    assert none.skipped[0].reason is SkipReason.NO_BASELINE
    assert "no earlier scan" in none.skipped[0].detail
    assert "database was unreachable" in down.skipped[0].detail
