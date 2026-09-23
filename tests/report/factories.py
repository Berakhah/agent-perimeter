"""Test factory for the census report: builds CensusRun/CensusRecord objects
in memory, never persisted to a session - census_report.py only ever reads
plain attributes off these, so a DB round-trip buys nothing here.

Two strata, matching the two shapes real code actually produces:

- Artifact stratum (census/run.py's `_record_for` + `detect.detect_features`):
  `feature_set_json = {"features": [...], "derivation": "artifact",
  "confidence": 0.6, "caveat": ..., "is_unknown": bool}`.
- Live-discover stratum (the shape `census/tier3.py`'s `Tier3Fingerprint`
  produced before that module was removed - see `docs/census/CHANGELOG.md`
  and `docs/open-decisions.md` decision 5 - never wired into any real
  CensusRecord): `feature_set_json = {"features": [...],
  "derivation": "probe", "confidence": 0.95, "caveat": ...}`.

`census_fixture()` defaults to zero live-discover records, matching this
project's actual current state - no live-discover stratum has ever run, and
none can under the current authorisation rules. Pass
`probe_supports`/`probe_unknown` to build synthetic live-discover data for
tests that exercise the two-stratum render path.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from agent_perimeter.db.models import CensusRecord, CensusRun
from agent_perimeter.model.census import Ecosystem, FetchStatus

SUPPORT_FEATURE = "server_discover"
_NOW = datetime(2026, 9, 1, tzinfo=UTC)
_ECOSYSTEMS = (Ecosystem.NPM, Ecosystem.PYPI)


def _artifact_record(
    *, run_id: int, idx: int, name: str, ecosystem: Ecosystem, is_unknown: bool, supports: bool
) -> CensusRecord:
    features = [SUPPORT_FEATURE] if supports and not is_unknown else []
    return CensusRecord(
        census_run_id=run_id,
        registry_id=f"registry/{name}",
        coords_digest=f"artifact-digest-{idx:04d}",
        ecosystem=ecosystem.value,
        package_name=name,
        distribution=f"package_{ecosystem.value}",
        sdk_version=None if is_unknown else "2.0.0",
        feature_set_json={
            "features": features,
            "derivation": "artifact",
            "confidence": 0.6,
            "caveat": None,
            "is_unknown": is_unknown,
        },
        fetch_status=FetchStatus.OK.value,
        fetch_detail="",
        rank_metric=None,
        rank_metric_source="seeded_random",
        collected_at=_NOW,
    )


def _probe_record(*, run_id: int, idx: int, supports: bool) -> CensusRecord:
    features = [SUPPORT_FEATURE] if supports else []
    return CensusRecord(
        census_run_id=run_id,
        registry_id=f"registry/remote-{idx}",
        coords_digest=f"probe-digest-{idx:04d}",
        ecosystem=None,
        package_name=None,
        distribution="remote_only",
        sdk_version=None,
        feature_set_json={
            "features": features,
            "derivation": "probe",
            "confidence": 0.95,
            "caveat": None,
        },
        fetch_status=(FetchStatus.OK if supports else FetchStatus.UNREACHABLE).value,
        fetch_detail="",
        rank_metric=None,
        rank_metric_source=None,
        collected_at=_NOW,
    )


def census_fixture(
    *,
    names: Sequence[str] | None = None,
    supports: int = 2,
    does_not_support: int = 2,
    unknown: int = 1,
    fetch_failures: int = 3,
    tier2_n: int = 200,
    sample_seed: int | None = 42,
    probe_supports: int = 0,
    probe_unknown: int = 0,
) -> tuple[CensusRun, list[CensusRecord]]:
    """A CensusRun plus artifact-stratum (and, optionally, live-discover-
    stratum) CensusRecord rows, split evenly across npm/pypi.

    `names`, when given, drives the record count directly: each name becomes
    one "supports" artifact record (used by the tests that check a
    third-party name never reaches the rendered report or the raw export).
    """
    run = CensusRun(
        id=1,
        started_at=_NOW,
        finished_at=_NOW,
        population_size=500,
        fetch_failures=fetch_failures,
        tool_version="0.1.0",
        method_hash="deadbeefcafef00d",
        tier2_n=tier2_n,
        sample_seed=sample_seed,
        registry_endpoint="https://registry.modelcontextprotocol.io/v0/servers",
    )
    assert run.id is not None

    records: list[CensusRecord] = []

    if names is not None:
        for i, name in enumerate(names):
            records.append(
                _artifact_record(
                    run_id=run.id,
                    idx=i,
                    name=name,
                    ecosystem=_ECOSYSTEMS[i % 2],
                    is_unknown=False,
                    supports=True,
                )
            )
    else:
        idx = 0
        for _ in range(supports):
            records.append(
                _artifact_record(
                    run_id=run.id,
                    idx=idx,
                    name=f"pkg-{idx}",
                    ecosystem=_ECOSYSTEMS[idx % 2],
                    is_unknown=False,
                    supports=True,
                )
            )
            idx += 1
        for _ in range(does_not_support):
            records.append(
                _artifact_record(
                    run_id=run.id,
                    idx=idx,
                    name=f"pkg-{idx}",
                    ecosystem=_ECOSYSTEMS[idx % 2],
                    is_unknown=False,
                    supports=False,
                )
            )
            idx += 1
        for _ in range(unknown):
            records.append(
                _artifact_record(
                    run_id=run.id,
                    idx=idx,
                    name=f"pkg-{idx}",
                    ecosystem=_ECOSYSTEMS[idx % 2],
                    is_unknown=True,
                    supports=False,
                )
            )
            idx += 1

    probe_idx = 0
    for _ in range(probe_supports):
        records.append(_probe_record(run_id=run.id, idx=probe_idx, supports=True))
        probe_idx += 1
    for _ in range(probe_unknown):
        records.append(_probe_record(run_id=run.id, idx=probe_idx, supports=False))
        probe_idx += 1

    return run, records
