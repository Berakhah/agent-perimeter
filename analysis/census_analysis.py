"""Recompute every published census figure from `records.csv` alone.

`records.csv` (written by `agent_perimeter.report.census_report.export_raw`,
one row per record, keyed by a digest - no names, no URLs) carries everything
needed to recompute per-stratum, per-ecosystem supports/does_not_support/
unknown counts: group by its `stratum`/`ecosystem` columns and count its
`supports_2026_07_28` column. That is the whole reproducibility claim - the
CSV alone, no database, no salt, no API key - and this script's success does
not depend on anything else existing.

`export_raw` also writes an optional `records.summary.json` sidecar next to
the CSV, carrying the same figures `render_census` put in the report's prose
and tables. When that sidecar is present, this script additionally checks its
own from-scratch recomputation against it and prints a pass/fail per line -
useful for catching drift between a specific publication and its own raw
data. When it is absent, the script still runs to completion and simply
prints the recomputed figures for a human to compare against the report by
eye.

Deliberately stdlib-only and free of any `agent_perimeter` import: two
independently-written computations agreeing (or a human eyeballing one
against the report) is the check, not this project's own aggregation code
vouching for itself.

    uv run python analysis/census_analysis.py docs/census/2026-09-01/records.csv

Expected, when a summary sidecar is present: every line reports `match`. A
`MISMATCH` line means the published report and the published raw data
disagree - report it, don't paper over it.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROW = "{label:<45} {published:>10} {computed:>10}  {result}"
SUMMARY_NAME = "records.summary.json"


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


def _figures(computed: dict[str, Any]) -> list[tuple[str, object]]:
    """Flatten `_recompute`'s output into (label, value) pairs, in the order
    the report states them: population->artifact figures, then live-discover.
    The single source of truth for "every number in the report" - both the
    summary-comparison path and the summary-less print-only path walk this
    same list, so they can never drift apart from each other.
    """
    out: list[tuple[str, object]] = [
        ("artifact.n_examined", computed["artifact"]["n_examined"]),
    ]
    for field in ("supports", "does_not_support", "unknown", "n"):
        out.append((f"artifact.pooled.{field}", computed["artifact"]["pooled"][field]))
    for eco, row in computed["artifact"]["by_ecosystem"].items():
        for field in ("supports", "does_not_support", "unknown", "n"):
            out.append((f"artifact.by_ecosystem.{eco}.{field}", row[field]))

    live = computed["live_discover"]
    if live is None:
        out.append(("live_discover", None))
    else:
        for field in ("n_sampled", "supports", "does_not_support", "unknown", "n"):
            out.append((f"live_discover.{field}", live[field]))
    return out


def _lookup(summary: dict[str, Any], label: str) -> object:
    """The summary's value for one dotted `_figures` label, or a sentinel
    string when the summary has nothing at that path (e.g. an ecosystem this
    CSV has rows for but the summary never recorded) - a genuine MISMATCH,
    not a KeyError.
    """
    node: Any = summary
    for part in label.split("."):
        if not isinstance(node, dict) or part not in node:
            return "<absent from summary>"
        node = node[part]
    return node


def check(csv_path: Path, summary_path: Path | None) -> bool:
    """Recompute every figure from `csv_path` alone, and - when
    `summary_path` is given and exists - check it against that sidecar.
    Always succeeds (returns True) when there is no sidecar to check
    against; only a real published-vs-recomputed disagreement fails.
    """
    computed = _recompute(csv_path)
    summary: dict[str, Any] | None = (
        json.loads(summary_path.read_text(encoding="utf-8"))
        if summary_path is not None and summary_path.is_file()
        else None
    )

    lines: list[str] = []
    all_ok = True
    if summary is None:
        print(f"(no {SUMMARY_NAME} next to {csv_path.name} - printing recomputed figures only)")
        for label, value in _figures(computed):
            lines.append(
                _ROW.format(label=label, published="-", computed=str(value), result="(no summary)")
            )
    else:
        for label, value in _figures(computed):
            all_ok = _compare(label, _lookup(summary, label), value, lines=lines) and all_ok

    for line in lines:
        print(line)
    return all_ok


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <path/to/records.csv>", file=sys.stderr)
        return 2
    csv_path = Path(argv[1])
    if not csv_path.is_file():
        print(f"no such file: {csv_path}", file=sys.stderr)
        return 2
    summary_path = csv_path.with_name(SUMMARY_NAME)

    ok = check(csv_path, summary_path)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
