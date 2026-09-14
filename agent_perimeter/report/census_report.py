"""The published census report. Aggregate only. Defines every term it uses.

Two populations, two methods, reported separately and never combined into one
percentage:

- **Artifact stratum** - npm/PyPI packages downloaded and feature-detected
  from source (`census/detect.detect_features`, `Derivation.ARTIFACT`).
  `CensusRecord.feature_set_json["derivation"] == "artifact"`.
- **Live-discover stratum** - a random sample of remote-only servers that
  each answered (or didn't) one live `server/discover` call
  (`census/tier3.py`, `Derivation.PROBE`).
  `CensusRecord.feature_set_json["derivation"] == "probe"`.

A majority of registry entries (56% in the 2026-09-14 run) have no fetchable
package at all (only a `remotes` URL - see docs/methodology.md), so the artifact stratum alone
cannot answer "what fraction of the public MCP ecosystem supports X". Both
strata get their own section, their own n, their own method sentence, and
their own headline claim. Nothing here sums them.

`CensusRecord` instances never reach the template context: `render_census`
reduces every record to an `Aggregate` (or a plain count) before Jinja ever
sees it. That is what makes "no third-party name or URL in the report" hold
structurally rather than by review.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from packaging.version import InvalidVersion, Version

from agent_perimeter.census.detect import SDK_FLOOR
from agent_perimeter.census.sample import SELECTION_METHOD
from agent_perimeter.db.models import CensusRecord, CensusRun
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords
from agent_perimeter.model.feature import Feature

TEMPLATES = Path(__file__).parent / "templates"

# The only revision this census currently tracks - see
# agent_perimeter/transport/features.yaml and TERM_DEFINITIONS below.
REVISION = "2026-07-28"
SUPPORT_FEATURE = "server_discover"

ARTIFACT_DERIVATION = "artifact"
PROBE_DERIVATION = "probe"

# Two-sided 95% normal quantile, for Aggregate.wilson95.
WILSON_Z = 1.959964

# The Tier 2 sampling frame: every `distribution` value that names a package
# ecosystem census/artifacts.py can fetch. `package_other` is a package
# coordinate too, but no fetcher is modelled for it, so it is not eligible.
ELIGIBLE_DISTRIBUTIONS: tuple[str, ...] = ("package_npm", "package_pypi")

TERM_DEFINITIONS: dict[str, str] = {
    "population": (
        "Every entry returned by the official MCP registry API between the collection "
        "window's start and end, including entries whose package coordinates could not "
        "be resolved."
    ),
    "sample": (
        "Tier 1 is the whole population. Tier 2 is a seeded uniform random sample of up "
        "to n packaged entries within each ecosystem, selected as described under Method."
    ),
    "supports 2026-07-28": (
        "The package's published artifact pins an MCP SDK at or above the version that "
        "introduced the revision's mandatory methods, and its source contains a handler "
        "for server/discover. This is a statement about a published artifact, not about "
        "any running deployment."
    ),
    "does not support 2026-07-28": (
        "The published artifact pins an SDK below that floor, or contains no such "
        "handler. It does not mean the software is insecure, and it does not mean a "
        "deployment is exposed."
    ),
    "unknown": (
        "The artifact was fetched and extracted, but it carries no SDK pin and no "
        "parseable source, so neither signal of the two-signals rule is available; or "
        "it carries no SDK pin at all, in which case any handler string in its source "
        "is dropped with a caveat, because a feature cannot be asserted without a pin "
        "at or above its floor. "
        "Reported separately and never folded into a denominator. Fetch failures are "
        "not unknowns: they are reported separately under the sample description and "
        "never enter the examined or unknown counts."
    ),
    "conformance gap": (
        "A server that claims a revision and does not exhibit a feature that revision "
        "requires. Measurable only against a live authorised target, so it appears in "
        "scan reports and never in this census."
    ),
    "live-discover sample": (
        "A random sample of remote-only registry entries (a remotes URL, no fetchable "
        "package), each sent exactly one unauthenticated server/discover request. A "
        "successful response confirms support; a non-response never confirms its "
        "absence, so this sample never reports a does-not-support count."
    ),
}


@dataclass(slots=True, frozen=True)
class Aggregate:
    supports: int
    does_not_support: int
    unknown: int

    @property
    def n(self) -> int:
        """Denominator excludes unknowns. Guessing at an unknown is the thing we sell against."""
        return self.supports + self.does_not_support

    @property
    def share(self) -> float | None:
        return None if self.n == 0 else self.supports / self.n

    @property
    def wilson95(self) -> tuple[float, float] | None:
        """Wilson score interval for `share` at 95% (z = 1.959964), or None
        when n == 0. Wilson rather than Wald because several cells are small
        and near zero, where Wald collapses to a zero-width or negative
        interval."""
        if self.n == 0:
            return None
        n = self.n
        p = self.supports / n
        z2 = WILSON_Z * WILSON_Z
        denominator = 1 + z2 / n
        centre = (p + z2 / (2 * n)) / denominator
        half_width = WILSON_Z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denominator
        return (max(0.0, centre - half_width), min(1.0, centre + half_width))


def _feature_list(feature_set_json: dict[str, object]) -> list[str]:
    features = feature_set_json.get("features")
    return [str(f) for f in features] if isinstance(features, list) else []


def _classify(record: CensusRecord) -> tuple[str, str] | None:
    """(stratum, bucket) for one record, or None if it belongs to neither
    stratum this report tracks (never attempted, or attempted and never
    resolved - e.g. a tier-1-only entry, or an artifact fetch that failed
    before feature detection ever ran).
    """
    fs: dict[str, object] = record.feature_set_json
    derivation = fs.get("derivation")
    supports_feature = SUPPORT_FEATURE in _feature_list(fs)

    if derivation == ARTIFACT_DERIVATION:
        if bool(fs.get("is_unknown")):
            return (ARTIFACT_DERIVATION, "unknown")
        return (ARTIFACT_DERIVATION, "supports" if supports_feature else "does_not_support")

    if derivation == PROBE_DERIVATION:
        # One server/discover request, no retry (census/tier3.py). A
        # non-answer is indistinguishable from an explicit rejection by
        # that module's own design (its requirement 3), so this stratum can
        # confirm support but never its absence - does_not_support is
        # structurally always 0 here, not a rounding artefact.
        return (PROBE_DERIVATION, "supports" if supports_feature else "unknown")

    return None


def aggregate(records: Sequence[CensusRecord]) -> dict[str, Aggregate]:
    """Per-revision counts for whatever records are passed in.

    Records with neither an artifact- nor probe-derived `feature_set_json`
    are skipped, not folded into "does not support" - see `_classify`. Pass
    a stratum- (and, for the artifact stratum, ecosystem-) homogeneous list
    to get a meaningful per-stratum figure; `render_census` does that
    filtering before ever calling this.
    """
    supports = does_not_support = unknown = 0
    for record in records:
        classified = _classify(record)
        if classified is None:
            continue
        _, bucket = classified
        if bucket == "supports":
            supports += 1
        elif bucket == "does_not_support":
            does_not_support += 1
        else:
            unknown += 1
    return {REVISION: Aggregate(supports, does_not_support, unknown)}


def _agg_dict(agg: Aggregate) -> dict[str, object]:
    """JSON-friendly view of an Aggregate: its three fields plus the derived
    properties, so the summary sidecar is self-describing and a reader (or
    `analysis/census_analysis.py`) can cross-check n/share without
    re-deriving the property formulas. `wilson95` is `[lo, hi]` or null.
    """
    ci = agg.wilson95
    return {
        **asdict(agg),
        "n": agg.n,
        "share": agg.share,
        "wilson95": None if ci is None else [ci[0], ci[1]],
    }


def _by_derivation(records: Sequence[CensusRecord], derivation: str) -> list[CensusRecord]:
    return [r for r in records if r.feature_set_json.get("derivation") == derivation]


def _digest_for(record: CensusRecord, salt: bytes) -> str:
    """A digest for the raw export, keyed by whatever `salt` the caller
    passes. `agent_perimeter/cli.py`'s `census` command passes the run's own
    persisted `CensusRun.salt` (`census/run.py::run_census` now sets it on
    the row it creates), so the exported digest matches the DB row's own
    `coords_digest` by construction - the two are no longer computed with
    two different, unrelated salts. Mirrors `PackageCoords.digest` / that
    same module's `_digest_for` fallback for a record with no resolvable
    package coordinates.
    """
    if record.ecosystem is not None and record.package_name is not None:
        coords = PackageCoords(ecosystem=Ecosystem(record.ecosystem), name=record.package_name)
        return coords.digest(salt)
    payload = f"registry:{record.registry_id.lower()}".encode()
    return hashlib.blake2b(payload, key=salt, digest_size=16).hexdigest()


# --- Sample description: population distribution, fetch failures, limits --

# Every `distribution` value census/run.py::_distribution can assign, in the
# order the report lists them. Any other value a record carries is still
# counted, appended after these.
DISTRIBUTIONS: tuple[str, ...] = (
    "remote_only",
    "package_npm",
    "package_pypi",
    "package_other",
    "none",
)

# `CensusRecord.fetch_detail` is free text from census/artifacts.py and can
# embed a package name or URL. It is never rendered. Each failure is bucketed
# by the first matching prefix below and reported under that fixed label only;
# a detail matching nothing lands in "other". Order matters: more specific
# prefixes first.
FETCH_FAILURE_CAUSES: tuple[tuple[str, str], ...] = (
    ("no downloadable artifact", "no downloadable artifact"),
    ("package not found", "package not found"),
    ("artifact not found", "artifact not found"),
    ("artifact request throttled", "artifact request throttled"),
    ("artifact request returned", "artifact request returned a non-200 status"),
    ("artifact download timed out", "artifact download timed out"),
    ("artifact download failed", "artifact download failed"),
    ("declared size exceeds", "declared size exceeds the archive cap"),
    ("download exceeds", "download exceeds the archive cap"),
    ("archive rejected: member exceeds", "archive rejected: member exceeds the per-file size cap"),
    ("archive rejected: member resolves outside", "archive rejected: path traversal member"),
    ("archive rejected: symlink member", "archive rejected: symlink member"),
    ("archive rejected: special file member", "archive rejected: special file member"),
    ("archive rejected: archive exceeds", "archive rejected: archive exceeds the size cap"),
    ("archive rejected: uncompressed size exceeds", "archive rejected: uncompressed size cap"),
    ("archive rejected", "archive rejected: other"),
    ("local filesystem error", "local filesystem error"),
)
OTHER_CAUSE = "other"
NOT_ATTEMPTED_STATUS = "not_attempted"
# detect.py attaches two "source mentions ..." caveats. Only the one where a
# *present* pin predates the floor is a does-not-support under-count; the
# other ("pins no SDK") marks a row that is reported as unknown, never as
# does-not-support, so it is not a limitation of the same kind.
FLOOR_DROPPED_CAVEAT_PREFIX = "source mentions "
FLOOR_DROPPED_CAVEAT_MARKER = "predates it"


def population_distribution(records: Sequence[CensusRecord]) -> dict[str, int]:
    """Count of records per `distribution` value, every known value present
    (zero included) so the table never silently omits a category."""
    counts: dict[str, int] = dict.fromkeys(DISTRIBUTIONS, 0)
    for record in records:
        counts[record.distribution] = counts.get(record.distribution, 0) + 1
    return counts


def _failure_cause(detail: str | None) -> str:
    text = detail or ""
    for prefix, label in FETCH_FAILURE_CAUSES:
        if text.startswith(prefix):
            return label
    return OTHER_CAUSE


def fetch_failure_breakdown(run: CensusRun, records: Sequence[CensusRecord]) -> dict[str, object]:
    """Split `run.fetch_failures` into registry-pagination vs artifact-fetch
    failures, with the artifact failures bucketed by fixed cause label and
    by ecosystem/status. `run.fetch_failures` is `log.failures + artifact
    failures` (census/run.py), so the registry share is the remainder.
    """
    artifact_failed = [
        r for r in records if r.fetch_status not in (FetchStatus.OK.value, NOT_ATTEMPTED_STATUS)
    ]
    by_cause: dict[str, int] = {}
    for record in artifact_failed:
        label = _failure_cause(record.fetch_detail)
        by_cause[label] = by_cause.get(label, 0) + 1

    by_ecosystem_status: dict[str, dict[str, int]] = {}
    for record in records:
        if record.ecosystem is None or record.fetch_status == NOT_ATTEMPTED_STATUS:
            continue
        row = by_ecosystem_status.setdefault(record.ecosystem, {})
        row[record.fetch_status] = row.get(record.fetch_status, 0) + 1

    artifact = len(artifact_failed)
    return {
        "total": run.fetch_failures,
        "registry_pagination": max(run.fetch_failures - artifact, 0),
        "artifact": artifact,
        "by_cause": dict(sorted(by_cause.items())),
        "by_ecosystem_status": {
            eco: dict(sorted(statuses.items()))
            for eco, statuses in sorted(by_ecosystem_status.items())
        },
    }


def _pin_at_or_above_floor(record: CensusRecord) -> bool:
    if record.sdk_version is None or record.ecosystem is None:
        return False
    floor = SDK_FLOOR.get(Feature(SUPPORT_FEATURE), {}).get(Ecosystem(record.ecosystem))
    if floor is None:
        return False
    try:
        return Version(record.sdk_version) >= Version(floor)
    except InvalidVersion:
        return False


def detection_limitations(artifact_records: Sequence[CensusRecord]) -> dict[str, dict[str, int]]:
    """Two known under-counts of the two-signals rule (pin AND source signal),
    per ecosystem:

    - `pinned_at_floor_without_handler`: the pin is at or above the
      server/discover floor but no handler string appears in shipped source,
      so the record counts as does_not_support. If the SDK serves the method
      on the package's behalf, that is a false does-not-support the artifact
      alone cannot resolve.
    - `floor_dropped_source_signal`: source mentions a revision feature but
      the pin predates the floor, so the pin wins (detect.py's caveat).
    """
    pinned = dict.fromkeys((e.value for e in Ecosystem), 0)
    dropped = dict.fromkeys((e.value for e in Ecosystem), 0)
    for record in artifact_records:
        classified = _classify(record)
        if classified is None or record.ecosystem not in pinned:
            continue
        if classified[1] == "does_not_support" and _pin_at_or_above_floor(record):
            pinned[record.ecosystem] += 1
        caveat = record.feature_set_json.get("caveat")
        if (
            isinstance(caveat, str)
            and caveat.startswith(FLOOR_DROPPED_CAVEAT_PREFIX)
            and FLOOR_DROPPED_CAVEAT_MARKER in caveat
        ):
            dropped[record.ecosystem] += 1
    return {
        "pinned_at_floor_without_handler": {**pinned, "total": sum(pinned.values())},
        "floor_dropped_source_signal": {**dropped, "total": sum(dropped.values())},
    }


def share_with_ci(agg: Aggregate) -> str:
    """`1.7% (95% CI 0.4–4.9%)`, or `n/a` when there is no denominator."""
    share, ci = agg.share, agg.wilson95
    if share is None or ci is None:
        return "n/a"
    return f"{share * 100:.1f}% (95% CI {ci[0] * 100:.1f}–{ci[1] * 100:.1f}%)"


def _ecosystem_breakdown(artifact_records: Sequence[CensusRecord]) -> dict[str, dict[str, object]]:
    breakdown: dict[str, dict[str, object]] = {}
    for eco in Ecosystem:
        eco_records = [r for r in artifact_records if r.ecosystem == eco.value]
        breakdown[eco.value] = {
            "n_examined": len(eco_records),
            "aggregate": aggregate(eco_records)[REVISION],
        }
    return breakdown


def render_census(run: CensusRun, records: Sequence[CensusRecord]) -> str:
    env = Environment(
        loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"])
    )
    template = env.get_template("census.html.j2")

    artifact_records = _by_derivation(records, ARTIFACT_DERIVATION)
    probe_records = _by_derivation(records, PROBE_DERIVATION)

    artifact_agg = aggregate(artifact_records)[REVISION]
    probe_agg = aggregate(probe_records)[REVISION] if probe_records else None

    distribution = population_distribution(records)
    eligible = sum(distribution.get(k, 0) for k in ELIGIBLE_DISTRIBUTIONS)
    return template.render(
        css=(TEMPLATES / "report.css").read_text(encoding="utf-8"),
        run=run,
        revision=REVISION,
        term_definitions=TERM_DEFINITIONS,
        selection_method=SELECTION_METHOD,
        share_ci=share_with_ci,
        artifact_agg=artifact_agg,
        artifact_n_examined=len(artifact_records),
        by_ecosystem=_ecosystem_breakdown(artifact_records),
        probe_agg=probe_agg,
        probe_n=len(probe_records),
        distribution=distribution,
        eligible_count=eligible,
        package_other_count=distribution.get("package_other", 0),
        remote_only_count=distribution.get("remote_only", 0),
        fetch_failures=fetch_failure_breakdown(run, records),
        limitations=detection_limitations(artifact_records),
        support_floor=SDK_FLOOR[Feature(SUPPORT_FEATURE)][Ecosystem.NPM],
    )


def export_raw(run: CensusRun, records: Sequence[CensusRecord], *, salt: bytes, out: Path) -> Path:
    """Write `records.csv` (one row per record, keyed by digest, no names or
    URLs) plus a `records.summary.json` sidecar carrying the same aggregate
    figures the report states. `analysis/census_analysis.py` recomputes the
    CSV from scratch and checks it against that sidecar - the reproducibility
    claim in the report's method section.
    """
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / "records.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "coords_digest",
                "stratum",
                "ecosystem",
                "sdk_version",
                "supports_2026_07_28",
                "fetch_status",
                "collected_at",
            ]
        )
        for record in records:
            classified = _classify(record)
            stratum = classified[0] if classified is not None else "unattempted"
            support_label = classified[1] if classified is not None else "n/a"
            writer.writerow(
                [
                    _digest_for(record, salt),
                    stratum,
                    record.ecosystem or "",
                    record.sdk_version or "",
                    support_label,
                    record.fetch_status,
                    record.collected_at.isoformat(),
                ]
            )

    artifact_records = _by_derivation(records, ARTIFACT_DERIVATION)
    probe_records = _by_derivation(records, PROBE_DERIVATION)
    summary = {
        "tool_version": run.tool_version,
        "method_hash": run.method_hash,
        "sample_seed": run.sample_seed,
        "revision": REVISION,
        "artifact": {
            "n_examined": len(artifact_records),
            "by_ecosystem": {
                eco.value: {
                    "n_examined": len([r for r in artifact_records if r.ecosystem == eco.value]),
                    **_agg_dict(
                        aggregate([r for r in artifact_records if r.ecosystem == eco.value])[
                            REVISION
                        ]
                    ),
                }
                for eco in Ecosystem
            },
            "pooled": _agg_dict(aggregate(artifact_records)[REVISION]),
        },
        "live_discover": (
            {"n_sampled": len(probe_records), **_agg_dict(aggregate(probe_records)[REVISION])}
            if probe_records
            else None
        ),
        # Sample description, so the sidecar carries what the report's
        # sample section states and a reader can diff the two.
        "population": {
            "size": run.population_size,
            "distribution": population_distribution(records),
        },
        "fetch_failures": fetch_failure_breakdown(run, records),
        "limitations": detection_limitations(artifact_records),
    }
    summary_path = out / "records.summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    return csv_path
