"""Census orchestration. Registry, then artifacts. No live server, ever."""

from __future__ import annotations

import hashlib
import inspect
import secrets
import shutil
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent_perimeter import __version__
from agent_perimeter.census import artifacts, detect, fetch, sample
from agent_perimeter.census.fetch import RegistryEntry
from agent_perimeter.census.sample import RankedEntry
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
    run: CensusRun, entry: RegistryEntry, ranked_by_id: dict[str, RankedEntry], salt: bytes
) -> CensusRecord:
    coords = entry.coords
    ranked_entry = ranked_by_id.get(entry.registry_id)
    return CensusRecord(
        census_run_id=run.id,
        registry_id=entry.registry_id,
        coords_digest=_digest_for(entry, salt),
        ecosystem=coords.ecosystem.value if coords is not None else None,
        package_name=coords.name if coords is not None else None,
        distribution=_distribution(entry),
        fetch_status=NOT_ATTEMPTED,
        rank_metric=ranked_entry.downloads if ranked_entry is not None else None,
        rank_metric_source=ranked_entry.rank_source.value if ranked_entry is not None else None,
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


def run_census(session: Session, client: httpx.Client, *, endpoint: str, tier2_n: int) -> CensusRun:
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

    # ponytail: salt generated per run and not persisted anywhere outside this
    # call. Task 7's export_raw needs a matching salt to publish coords_digest
    # after the embargo - wire a store for it when that task lands.
    salt = secrets.token_bytes(32)

    entries = list(fetch.paginate(client, endpoint, log))
    run.population_size = len(entries)

    ranked = sample.rank(client, entries)
    ranked_by_id = {r.entry.registry_id: r for r in ranked}
    tier2 = {r.entry.registry_id for r in sample.top_n(ranked, tier2_n)}

    for entry in entries:
        record = _record_for(run, entry, ranked_by_id, salt)
        if entry.registry_id in tier2 and entry.coords is not None:
            result = artifacts.fetch_artifact(client, entry.coords)
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
