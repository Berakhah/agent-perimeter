"""Recompute the published census numbers from the raw CSV alone, and check
them against the sidecar the report was actually built from.

`agent_perimeter.report.census_report.export_raw` writes two files into a
publication directory: `records.csv` (one row per record, keyed by a digest -
no names, no URLs) and `records.summary.json` (the same aggregate figures
`render_census` puts in the report's prose and tables, computed by the same
`aggregate()` call). This script reads `records.csv`, recomputes every one of
those figures from scratch using nothing but the stdlib, and prints each one
next to the summary's figure with a pass/fail per line.

Deliberately stdlib-only and free of any `agent_perimeter` import: the
reproducibility claim is that a stranger with the published CSV and its
summary sidecar - no database, no salt, no API key - can verify the report,
without even needing to trust this project's own aggregation code was called
correctly. Two independently-written computations agreeing is the check.

    uv run python analysis/census_analysis.py docs/census/2026-09-01/records.csv

Expected: every line reports `match`. A `MISMATCH` line means the published
report and the published raw data disagree - report it, don't paper over it.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROW = "{label:<45} {published:>10} {computed:>10}  {result}"


def _recompute(csv_path: Path) -> dict[str, Any]:
    """Group `records.csv` rows by stratum (and, for the artifact stratum,
    ecosystem), and count each group's supports/does_not_support/unknown -
    exactly what `agent_perimeter.report.census_report.aggregate` does,
    reimplemented here from the CSV's plain string columns alone.
    """
    artifact_by_eco: dict[str, Counter[str]] = {}
    artifact_total: Counter[str] = Counter()
    probe_total: Counter[str] = Counter()

    with csv_path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            stratum = row["stratum"]
            label = row["supports_2026_07_28"]
            if stratum == "artifact":
                artifact_total[label] += 1
                artifact_by_eco.setdefault(row["ecosystem"], Counter())[label] += 1
            elif stratum == "probe":
                probe_total[label] += 1

    def _agg(counts: Counter[str]) -> dict[str, object]:
        supports = counts.get("supports", 0)
        does_not_support = counts.get("does_not_support", 0)
        unknown = counts.get("unknown", 0)
        n = supports + does_not_support
        return {
            "supports": supports,
            "does_not_support": does_not_support,
            "unknown": unknown,
            "n": n,
            "share": None if n == 0 else supports / n,
        }

    return {
        "artifact": {
            "n_examined": sum(artifact_total.values()),
            "by_ecosystem": {eco: _agg(c) for eco, c in artifact_by_eco.items()},
            "pooled": _agg(artifact_total),
        },
        "live_discover": (
            {"n_sampled": sum(probe_total.values()), **_agg(probe_total)}
            if probe_total
            else None
        ),
    }


def _compare(label: str, published: object, computed: object, *, lines: list[str]) -> bool:
    ok = published == computed
    lines.append(
        _ROW.format(
            label=label,
            published=str(published),
            computed=str(computed),
            result="match" if ok else "MISMATCH",
        )
    )
    return ok


def check(csv_path: Path, summary_path: Path) -> bool:
    summary: Any = json.loads(summary_path.read_text(encoding="utf-8"))
    computed = _recompute(csv_path)

    lines: list[str] = []
    all_ok = True

    all_ok &= _compare(
        "artifact.n_examined",
        summary["artifact"]["n_examined"],
        computed["artifact"]["n_examined"],
        lines=lines,
    )
    for field in ("supports", "does_not_support", "unknown", "n"):
        all_ok &= _compare(
            f"artifact.pooled.{field}",
            summary["artifact"]["pooled"][field],
            computed["artifact"]["pooled"][field],
            lines=lines,
        )
    for eco, published_row in summary["artifact"]["by_ecosystem"].items():
        computed_row = computed["artifact"]["by_ecosystem"].get(
            eco, {"supports": 0, "does_not_support": 0, "unknown": 0, "n": 0}
        )
        for field in ("supports", "does_not_support", "unknown", "n"):
            all_ok &= _compare(
                f"artifact.by_ecosystem.{eco}.{field}",
                published_row[field],
                computed_row[field],
                lines=lines,
            )

    published_live = summary["live_discover"]
    computed_live = computed["live_discover"]
    if published_live is None or computed_live is None:
        all_ok &= _compare("live_discover", published_live, computed_live, lines=lines)
    else:
        for field in ("n_sampled", "supports", "does_not_support", "unknown", "n"):
            all_ok &= _compare(
                f"live_discover.{field}",
                published_live[field],
                computed_live[field],
                lines=lines,
            )

    for line in lines:
        print(line)
    return all_ok


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <path/to/records.csv>", file=sys.stderr)
        return 2
    csv_path = Path(argv[1])
    summary_path = csv_path.with_name("records.summary.json")
    if not csv_path.is_file():
        print(f"no such file: {csv_path}", file=sys.stderr)
        return 2
    if not summary_path.is_file():
        print(f"no summary sidecar next to {csv_path}: expected {summary_path}", file=sys.stderr)
        return 2

    ok = check(csv_path, summary_path)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
