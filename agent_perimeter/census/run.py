"""Census orchestration. Registry, then artifacts. No live server, ever."""

from __future__ import annotations

import hashlib
import inspect
import secrets
import shutil
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_perimeter import __version__
from agent_perimeter.census import artifacts, detect, fetch, sample
from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.db.models import CensusRecord, CensusRun
from agent_perimeter.model.census import FetchStatus

# Every record's artifact-fetch stage is either attempted (and gets a real
# FetchStatus value) or never attempted at all (tier 1, or tier 2 with no
# coords to fetch). fetch_status is NOT NULL, so "never attempted" needs its
# own value distinct from every real FetchStatus outcome - conflating it with
# e.g. NOT_FOUND would misreport a tier-1 entry as a failed fetch.
NOT_ATTEMPTED = "not_attempted"


def method_hash() -> str:
    """Hash of the collection code itself, so a published number names its method.

    B9 requires versioned results. Hashing the four modules that decide what gets
    collected means a changed method cannot silently reuse an old report's label.
    """
    h = hashlib.sha256()
    for module in (fetch, artifacts, detect, sample):
        h.update(inspect.getsource(module).encode())
    return h.hexdigest()[:16]


def _distribution(entry: RegistryEntry) -> str:
    """Task 2's revision: ~70% of the registry has no artifact at all. Every
    entry gets a distribution, not just the ones with a package."""
    if entry.coords is not None:
        return f"package_{entry.coords.ecosystem.value}"
    if entry.has_unmodeled_package:
        return "package_other"
    if entry.remotes:
        return "remote_only"
    return "none"


def _digest_for(entry: RegistryEntry, salt: bytes) -> str:
    """Same pseudonym construction as PackageCoords.digest, for an entry that
    may have no PackageCoords at all (remote-only, or no package/remote)."""
    if entry.coords is not None:
        return entry.coords.digest(salt)
    payload = f"registry:{entry.registry_id.lower()}".encode()
    return hashlib.blake2b(payload, key=salt, digest_size=16).hexdigest()


def _record_for(
    run: CensusRun, entry: RegistryEntry, selected: set[str], salt: bytes
) -> CensusRecord:
    coords = entry.coords
    return CensusRecord(
        census_run_id=run.id,
        registry_id=entry.registry_id,
        coords_digest=_digest_for(entry, salt),
        ecosystem=coords.ecosystem.value if coords is not None else None,
        package_name=coords.name if coords is not None else None,
        distribution=_distribution(entry),
        fetch_status=NOT_ATTEMPTED,
        # No download ranking exists any more (Task 7): the column stays in
        # the schema and is always None. rank_metric_source names the
        # selection method for a tier-2 entry so a reader can tell "drawn"
        # from "never eligible" without re-running the draw.
        rank_metric=None,
        rank_metric_source=sample.SELECTION_SOURCE if entry.registry_id in selected else None,
        collected_at=datetime.now(UTC),
    )


def _record_failures(session: Session, run: CensusRun) -> int:
    """Artifact-fetch failures among this run's records, counted separately
    from `log.failures` (registry-pagination failures) so `fetch_failures`
    reflects every network attempt that failed, not just page fetches.
    `NOT_ATTEMPTED` is not a failure - it means no request was ever made.
    """
    statuses = session.execute(
        select(CensusRecord.fetch_status).where(CensusRecord.census_run_id == run.id)
    ).scalars()
    return sum(1 for status in statuses if status not in (FetchStatus.OK.value, NOT_ATTEMPTED))


def run_census(
    session: Session,
    client: httpx.Client,
    *,
    endpoint: str,
    tier2_n: int,
    seed: int | None = None,
    progress: Callable[[str], None] | None = None,
) -> CensusRun:
    """Collect the census: paginate the registry, draw tier 2, fetch its artifacts.

    `seed` is the tier-2 sample seed; generated (and persisted on the run) when
    None so every run is reproducible from its own row. `progress` receives a
    short line at each stage so a real run over ~32k entries is never a black box.
    """
    _say = progress or (lambda _m: None)
    started = datetime.now(UTC)
    log = fetch.FetchLog()
    run = CensusRun(
        started_at=started,
        population_size=0,
        tool_version=__version__,
        method_hash=method_hash(),
        tier2_n=tier2_n,
        registry_endpoint=endpoint,
    )
    session.add(run)
    session.flush()

    # Persisted on the run itself (CensusRun.salt) so export_raw can later
    # recompute a digest that actually matches this run's own
    # coords_digest column - see that function's _digest_for docstring.
    salt = secrets.token_bytes(32)
    run.salt = salt

    entries = list(fetch.paginate(client, endpoint, log))
    run.population_size = len(entries)
    _say(f"population: {len(entries)} entries")

    seed = secrets.randbits(32) if seed is None else seed
    run.sample_seed = seed
    selected = {e.registry_id for e in sample.select(entries, tier2_n, seed)}
    _say(f"tier 2: selected {len(selected)} packaged entries with seed {seed}")

    done = 0
    for entry in entries:
        record = _record_for(run, entry, selected, salt)
        if entry.registry_id in selected and entry.coords is not None:
            result = artifacts.fetch_artifact(client, entry.coords)
            done += 1
            if done % 25 == 0 or done == len(selected):
                _say(f"artifacts: {done}/{len(selected)}")
            record.fetch_status = result.status.value
            record.fetch_detail = result.detail
            if result.root is not None:
                try:
                    fp = detect.detect_features(result.root)
                    record.sdk_version = fp.sdk_version
                    record.feature_set_json = {
                        "features": sorted(f.value for f in fp.features),
                        "derivation": (
                            fp.claim.derivation.value if fp.claim.derivation is not None else None
                        ),
                        "confidence": fp.claim.confidence,
                        "caveat": fp.claim.caveat,
                        "is_unknown": fp.is_unknown,
                    }
                finally:
                    # Task 3's fetch_artifact leaves ArtifactResult.root
                    # caller-owned; run_census is the caller. Left uncleaned,
                    # a real census of hundreds of packages leaks up to
                    # MAX_UNCOMPRESSED_BYTES of temp files per package for the
                    # run's lifetime.
                    shutil.rmtree(result.root, ignore_errors=True)
        session.add(record)

    run.fetch_failures = log.failures + _record_failures(session, run)
    run.finished_at = datetime.now(UTC)
    session.commit()
    return run
