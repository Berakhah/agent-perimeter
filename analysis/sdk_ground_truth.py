"""Artifact-derived feature detection over real packages, printed for a human
to compare against a live-probe result by hand.

What this script does NOT do: the "live-fingerprint" half of the ground-truth
exercise (running this project's own live scanner against each package's
running server, inside the Week 1 sandboxed stdio container - see
agent_perimeter/transport/stdio.py) is separate, heavier infrastructure this
script does not attempt. A human has to actually stand each server up and run
that scanner themselves.

What this script DOES do: for each (ecosystem, name) pair, call
census.artifacts.fetch_artifact() to download and safely extract the published
artifact (never executed), then census.detect.detect_features() to derive its
FeatureSet from source alone, and print sdk_version / is_unknown / features -
plus a blank column for the human to fill in with what the live probe actually
saw. Comparing the two columns, across a real sample, is the empirical basis
for agent_perimeter.census.detect.ARTIFACT_CONFIDENCE, which today is a stated
placeholder (0.6) - see docs/methodology.md "## SDK version floors" for the
same caveat about the SDK_FLOOR versions this module's detection depends on.

Not part of the test suite - nothing here is imported or run by pytest. It is
a tool for a human to run against the real internet:

    uv run python analysis/sdk_ground_truth.py
    uv run python analysis/sdk_ground_truth.py path/to/pairs.txt

where a pairs file has one "ecosystem,name" pair per line, e.g.:

    pypi,some-real-mcp-server
    npm,@some-scope/some-real-mcp-server
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import httpx

from agent_perimeter.census.artifacts import fetch_artifact
from agent_perimeter.census.detect import detect_features
from agent_perimeter.model.census import Ecosystem, FetchStatus, PackageCoords

# Placeholder sample only - not confirmed to exist on the live registry today.
# For the real ~30-package exercise, replace this with coordinates pulled from
# an actual agent_perimeter.census.fetch.paginate() run against the registry.
DEFAULT_SAMPLE: list[tuple[str, str]] = [
    ("pypi", "mcp"),
    ("npm", "@modelcontextprotocol/sdk"),
]

_ROW = "{package:<42} {sdk_version:<14} {is_unknown:<11} {features:<45} {live}"


def _load_pairs(path: Path | None) -> list[tuple[str, str]]:
    if path is None:
        return DEFAULT_SAMPLE
    pairs: list[tuple[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        ecosystem, _, name = line.partition(",")
        pairs.append((ecosystem.strip(), name.strip()))
    return pairs


def main(argv: list[str]) -> None:
    path = Path(argv[1]) if len(argv) > 1 else None
    pairs = _load_pairs(path)

    print(
        _ROW.format(
            package="package",
            sdk_version="sdk_version",
            is_unknown="is_unknown",
            features="artifact-derived features",
            live="live_observed (fill in by hand)",
        )
    )
    with httpx.Client() as client:
        for eco_name, name in pairs:
            try:
                ecosystem = Ecosystem(eco_name)
            except ValueError:
                print(f"{name}: skipped, unrecognised ecosystem {eco_name!r}")
                continue

            result = fetch_artifact(client, PackageCoords(ecosystem=ecosystem, name=name))
            if result.status is not FetchStatus.OK or result.root is None:
                print(f"{name}: fetch failed - {result.status.value}: {result.detail}")
                continue

            fingerprint = detect_features(result.root)
            features = ",".join(sorted(f.value for f in fingerprint.features)) or "-"
            print(
                _ROW.format(
                    package=f"{name}@{result.version}",
                    sdk_version=str(fingerprint.sdk_version),
                    is_unknown=str(fingerprint.is_unknown),
                    features=features,
                    live="<fill in>",
                )
            )
            # Courtesy cleanup for a real multi-package run - fetch_artifact's
            # own docstring makes root caller-owned; nothing else here reads it
            # again once printed.
            shutil.rmtree(result.root.parent, ignore_errors=True)


if __name__ == "__main__":
    main(sys.argv)
