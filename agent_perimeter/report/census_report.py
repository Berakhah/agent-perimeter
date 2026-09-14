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

Roughly 70% of registry entries have no fetchable package at all (only a
`remotes` URL - see docs/methodology.md), so the artifact stratum alone
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
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agent_perimeter.census.sample import SELECTION_METHOD
from agent_perimeter.db.models import CensusRecord, CensusRun
from agent_perimeter.model.census import Ecosystem, PackageCoords

TEMPLATES = Path(__file__).parent / "templates"

# The only revision this census currently tracks - see
# agent_perimeter/transport/features.yaml and TERM_DEFINITIONS below.
REVISION = "2026-07-28"
SUPPORT_FEATURE = "server_discover"

ARTIFACT_DERIVATION = "artifact"
PROBE_DERIVATION = "probe"

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
        "Coordinates could not be resolved, the artifact could not be fetched, or the "
        "source could not be parsed. Reported separately and never folded into a "
        "denominator."
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
    """JSON-friendly view of an Aggregate: its three fields plus the two
    derived properties, so the summary sidecar is self-describing and a
    reader (or `analysis/census_analysis.py`) can cross-check n/share
    without re-deriving the property formulas.
    """
    return {**asdict(agg), "n": agg.n, "share": agg.share}


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

    return template.render(
        css=(TEMPLATES / "report.css").read_text(encoding="utf-8"),
        run=run,
        revision=REVISION,
        term_definitions=TERM_DEFINITIONS,
        selection_method=SELECTION_METHOD,
        artifact_agg=artifact_agg,
        artifact_n_examined=len(artifact_records),
        by_ecosystem=_ecosystem_breakdown(artifact_records),
        probe_agg=probe_agg,
        probe_n=len(probe_records),
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
    }
    summary_path = out / "records.summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    return csv_path
