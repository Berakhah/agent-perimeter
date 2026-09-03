"""Tier-3 census: one unauthenticated server/discover probe per sampled host.

Tiers 1-2 are passive: registry pagination and downloaded package artifacts,
never a live server. Tier 3 is the one deliberate, tightly-scoped exception -
it sends exactly one JSON-RPC request to a random sample of real MCP servers
in the registry's remote-only stratum (a remotes URL but no fetchable package
artifact). It never sends any other method: no initialize, no tools/list, no
tool invocation, no fallback, no retry.

Safeguards, all structural rather than policy: honour a maintainer-editable
opt-out list first; honour robots.txt next; rate-limit between requests;
identify the tool and a contact address in the User-Agent (reused from
fetch.py's own constant, not duplicated here); and once a host fails to
answer, record it unreachable so a caller can exclude it from every future
sample. Every target - the sampled entries, the opt-out set - comes from data
passed into this module's functions; nothing here names a real host (see
test_tier3_sends_exactly_one_method_and_owns_no_host in
tests/census/test_passive_only.py, which asserts exactly that over this
file's own source).

No DB session lives here. sample_frame() takes the set of already-contacted
registry ids as a plain parameter; a caller (run.py, in a later integration)
is responsible for looking that set up from prior CensusRecord rows - e.g. a
FetchStatus.UNREACHABLE outcome from an earlier run - and threading it back
in. That keeps this module testable and importable on its own, with no
coupling to sqlalchemy or to run.py's orchestration.
"""

from __future__ import annotations

import random
import time
from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import httpx

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.census.fetch import USER_AGENT, RegistryEntry
from agent_perimeter.model.census import FetchStatus
from agent_perimeter.model.feature import Feature, FeatureSet

__all__ = [
    "USER_AGENT",
    "SAMPLE_SIZE",
    "TIER3_MIN_INTERVAL_S",
    "SkipReason",
    "SampleFrame",
    "Tier3Fingerprint",
    "HostResult",
    "remote_only_stratum",
    "sample_frame",
    "load_opt_out_hosts",
    "probe_host",
    "run_tier3",
]

# Requirement 2: n = 100, per the remote-only stratum, per run.
SAMPLE_SIZE = 100

# ponytail: fixed interval rather than a token bucket, same tradeoff as
# fetch.MIN_INTERVAL_S. This talks to arbitrary third-party operators with no
# published rate limit at all, so it errs slower than the registry's own
# 0.5s; swap for a bucket if a real deployment's Retry-After ever demands more.
TIER3_MIN_INTERVAL_S = 1.0

_ROBOTS_TIMEOUT_S = 10.0
_DISCOVER_TIMEOUT_S = 10.0
_JSONRPC_ID = 1

# Strictly the live-probe confidence transport.revision.py uses for the same
# reason (a server actually answered), duplicated rather than imported: this
# module must never import agent_perimeter.transport at all - see
# test_census_can_never_reach_a_transport_or_an_active_check, which applies
# to every file under agent_perimeter/census including this one.
LIVE_PROBE_CONFIDENCE = 0.95


class SkipReason(StrEnum):
    """Why a sampled host was never contacted at all - no request was sent."""

    OPTED_OUT = "opted_out"
    ROBOTS_DISALLOWED = "robots_disallowed"
    NO_REMOTE_URL = "no_remote_url"


@dataclass(slots=True, frozen=True)
class SampleFrame:
    """A reproducible draw: the seed, the eligible population, and the sample.

    Requirement 10: a reader who has the same registry snapshot, the same
    `already_contacted` set, and this seed can redraw `sample` and confirm it
    matches - that is what "publish the seed and a frame snapshot" buys.
    """

    seed: int
    eligible: tuple[RegistryEntry, ...]
    sample: tuple[RegistryEntry, ...]


@dataclass(slots=True, frozen=True)
class Tier3Fingerprint:
    """Mirrors transport.revision.Fingerprint / detect.ArtifactFingerprint:
    same features type, this time from exactly one live discover call."""

    features: FeatureSet
    protocol_versions_advertised: tuple[str, ...]
    claim: Claim


@dataclass(slots=True, frozen=True)
class HostResult:
    registry_id: str
    target_url: str | None
    status: FetchStatus | None
    """None means no request was ever sent - see `skip_reason`."""
    skip_reason: SkipReason | None
    fingerprint: Tier3Fingerprint | None


def remote_only_stratum(entries: Iterable[RegistryEntry]) -> list[RegistryEntry]:
    """Task 2's remote_only classification, restated here rather than
    imported from census.run (a private `_distribution` helper there, and
    importing run.py from here would risk a cycle once run.py integrates
    tier3). Keep the predicate in sync with census.run._distribution: a
    remotes URL, no package coords, and no unmodeled package either.
    """
    return [e for e in entries if e.coords is None and not e.has_unmodeled_package and e.remotes]


def sample_frame(
    entries: Sequence[RegistryEntry],
    *,
    n: int = SAMPLE_SIZE,
    seed: int,
    already_contacted: AbstractSet[str] = frozenset(),
) -> SampleFrame:
    """Seeded random sample of `n` from the remote-only stratum.

    Deterministic given the same entries, seed, and already_contacted set -
    same principle as sample.top_n's deterministic ranking. A registry_id in
    `already_contacted` is dropped from the eligible pool before the draw, so
    it can never be resampled: this is what makes "never contacted again,
    including on a re-run" hold once a caller feeds a prior UNREACHABLE
    outcome back in here.
    """
    pool = [e for e in remote_only_stratum(entries) if e.registry_id not in already_contacted]
    rng = random.Random(seed)  # noqa: S311 -- reproducibility requires a seedable PRNG, not `secrets`
    chosen = rng.sample(pool, k=min(n, len(pool)))
    return SampleFrame(seed=seed, eligible=tuple(pool), sample=tuple(chosen))


def load_opt_out_hosts(path: Path) -> frozenset[str]:
    """Maintainer-editable opt-out list: one hostname per line.

    Blank lines and `#`-prefixed comments are ignored. A missing file is an
    empty opt-out set, not an error - there is nothing wrong with never
    having needed one yet.
    """
    if not path.is_file():
        return frozenset()
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(
        stripped.lower()
        for line in lines
        if (stripped := line.strip()) and not stripped.startswith("#")
    )


def _robots_txt_url(target_url: str) -> str:
    parts = urlsplit(target_url)
    return urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))


def _robots_allows(client: httpx.Client, target_url: str, user_agent: str) -> bool:
    """Fetch the target host's robots.txt and honour any rule covering the
    probe URL. Fails closed: anything other than a clean 200 (parse and
    obey) or 404 (nothing published, nothing to obey) skips the host rather
    than risk proceeding past rules this fetch could not actually read.
    """
    robots_url = _robots_txt_url(target_url)
    try:
        response: httpx.Response | None = client.get(
            robots_url, headers={"User-Agent": user_agent}, timeout=_ROBOTS_TIMEOUT_S
        )
    except httpx.HTTPError:
        response = None
    time.sleep(TIER3_MIN_INTERVAL_S)

    if response is None:
        return False
    if response.status_code == 404:
        return True
    if response.status_code != 200:
        return False
    parser = RobotFileParser()
    parser.parse(response.text.splitlines())
    return parser.can_fetch(user_agent, target_url)


def _discover(client: httpx.Client, target_url: str, user_agent: str) -> dict[str, object] | None:
    """Send exactly one server/discover JSON-RPC request. None means "no
    answer": a network failure, a non-200 status, an unparseable body, or a
    JSON-RPC response with no `result` (a well-formed JSON-RPC error
    included) - every one of those is recorded as unreachable and never
    retried, deliberately not distinguished any further (requirement 3).
    """
    body = {"jsonrpc": "2.0", "id": _JSONRPC_ID, "method": "server/discover", "params": {}}
    try:
        response: httpx.Response | None = client.post(
            target_url, json=body, headers={"User-Agent": user_agent}, timeout=_DISCOVER_TIMEOUT_S
        )
    except httpx.HTTPError:
        response = None
    time.sleep(TIER3_MIN_INTERVAL_S)

    if response is None or response.status_code != 200:
        return None
    try:
        doc = response.json()
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    result = doc.get("result")
    return result if isinstance(result, dict) else None


def _observed_features(discover: dict[str, object]) -> frozenset[Feature]:
    """Observe or abstain, same discipline as transport.revision.fingerprint
    (this module cannot import that - see the module docstring). A discover
    call can only ever grant SERVER_DISCOVER (we got a result at all) and
    EXTENSIONS (capabilities.extensions present); every other Feature needs
    tools/list, an open stream, or a multi-step probe, none of which tier3
    ever sends, so none of them is ever inferred from this response no
    matter what other fields it happens to carry.
    """
    observed = {Feature.SERVER_DISCOVER}
    capabilities = discover.get("capabilities")
    if isinstance(capabilities, dict) and "extensions" in capabilities:
        observed.add(Feature.EXTENSIONS)
    return frozenset(observed)


def _fingerprint(discover: dict[str, object]) -> Tier3Fingerprint:
    features = _observed_features(discover)
    versions_raw = discover.get("protocolVersions")
    versions = tuple(str(v) for v in versions_raw) if isinstance(versions_raw, list) else ()
    claim = Claim(
        value=sorted(f.value for f in features),
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        confidence=LIVE_PROBE_CONFIDENCE,
        observed_at=datetime.now(UTC),
    )
    return Tier3Fingerprint(features=features, protocol_versions_advertised=versions, claim=claim)


def probe_host(
    client: httpx.Client,
    entry: RegistryEntry,
    *,
    user_agent: str = USER_AGENT,
    opt_out_hosts: AbstractSet[str] = frozenset(),
) -> HostResult:
    """Opt-out list, then robots.txt, then (at most) one server/discover
    call - checked in that order, each one gating the next, never logged
    but proceeded past (requirement 7: opt-out is checked before robots.txt
    too, not just before the discover call).
    """
    if not entry.remotes:
        return HostResult(entry.registry_id, None, None, SkipReason.NO_REMOTE_URL, None)
    target_url = entry.remotes[0]
    hostname = (urlsplit(target_url).hostname or "").lower()

    if hostname in opt_out_hosts:
        return HostResult(entry.registry_id, target_url, None, SkipReason.OPTED_OUT, None)

    if not _robots_allows(client, target_url, user_agent):
        return HostResult(entry.registry_id, target_url, None, SkipReason.ROBOTS_DISALLOWED, None)

    discover = _discover(client, target_url, user_agent)
    if discover is None:
        return HostResult(entry.registry_id, target_url, FetchStatus.UNREACHABLE, None, None)
    return HostResult(entry.registry_id, target_url, FetchStatus.OK, None, _fingerprint(discover))


def run_tier3(
    client: httpx.Client,
    frame: SampleFrame,
    *,
    user_agent: str = USER_AGENT,
    opt_out_hosts: AbstractSet[str] = frozenset(),
) -> tuple[HostResult, ...]:
    """Probe every host in `frame.sample`, in order. Never wired into
    census.run.run_census by this module - that integration, if it happens,
    is a later task's call.
    """
    return tuple(
        probe_host(client, entry, user_agent=user_agent, opt_out_hosts=opt_out_hosts)
        for entry in frame.sample
    )
