"""Derive a FeatureSet from a published artifact's source. Never run it.

Two independent signals must agree before a feature is asserted: the pinned
MCP SDK version (a package pinned to an SDK release predating the 2026-07-28
revision cannot serve it, regardless of what its own source says) and a scan
of the source for the handlers that revision requires. Where the two
disagree, the lower wins and a caveat is attached - a claim that hedges is
worth more than a claim that is wrong.

Detection reads text only: an `ast` parse for Python (parse, never compile or
run) and a plain token scan for JavaScript. Nothing here imports, compiles,
or runs a line of the artifact - see test_detection_never_imports_the_artifact
for the grep-verifiable half of that promise.
"""

from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packaging.version import InvalidVersion, Version

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.census import Ecosystem
from agent_perimeter.model.feature import Feature, FeatureSet

# Strictly below transport.revision.LIVE_PROBE_CONFIDENCE. An artifact tells you
# what a package could do, not what a deployment does.
ARTIFACT_CONFIDENCE = 0.6

# Lowest SDK release that can serve each feature, per ecosystem. Below the
# floor, source evidence is discarded: a package cannot serve what its pinned
# dependency cannot express.
#
# Verified 2026-09-09 against the real MCP SDK release history - see
# docs/methodology.md "## SDK version floors" for release dates and
# changelog URLs. Both ecosystems ship all four gated features together in
# their first 2.0.0 release: server/discover, resultType, CacheableResult,
# and MRTR are wire-level parts of the same 2026-07-28 protocol revision, not
# features an SDK adopts piecemeal. PARAM_HEADERS deliberately has no entry:
# it is a JSON Schema annotation convention, not an API the SDK itself gates
# by version, so source evidence for it stands on its own (see
# SOURCE_SIGNALS below).
SDK_FLOOR: dict[Feature, dict[Ecosystem, str]] = {
    Feature.SERVER_DISCOVER: {Ecosystem.PYPI: "2.0.0", Ecosystem.NPM: "2.0.0"},
    Feature.RESULT_TYPE: {Ecosystem.PYPI: "2.0.0", Ecosystem.NPM: "2.0.0"},
    Feature.CACHEABLE_RESULT: {Ecosystem.PYPI: "2.0.0", Ecosystem.NPM: "2.0.0"},
    Feature.MRTR: {Ecosystem.PYPI: "2.0.0", Ecosystem.NPM: "2.0.0"},
}

# Text signals a feature's handler leaves in source. Matched against raw file
# text - a hit is evidence, not proof, which is exactly why SDK_FLOOR exists
# to bound it.
SOURCE_SIGNALS: dict[Feature, re.Pattern[str]] = {
    Feature.SERVER_DISCOVER: re.compile(r"""["']server/discover["']"""),
    Feature.RESULT_TYPE: re.compile(r"\bresultType\b|\bresult_type\b"),
    Feature.CACHEABLE_RESULT: re.compile(r"\bttlMs\b|\bcacheScope\b|\bcache_scope\b"),
    Feature.MRTR: re.compile(r"\bInputRequiredResult\b|\binputResponses\b"),
    Feature.PARAM_HEADERS: re.compile(r"\bx-mcp-header\b", re.I),
}

_PY_SDK_NAMES = {"mcp", "modelcontextprotocol"}
# @modelcontextprotocol/sdk is the v1 monolithic package - frozen at 1.30.0,
# it never shipped a 2.x release (checked against the npm registry
# 2026-09-09). v2 split the SDK into packages that version together; a
# server implementation depends on @modelcontextprotocol/server, and some
# pin @modelcontextprotocol/core (its shared-schema dependency) directly.
# Recognising both v1 and v2 names is what lets _apply_sdk_floor gate a
# v1-pinned package correctly instead of treating an unrecognised package
# name as "no pin, cannot rule out".
_JS_SDK_NAMES = {
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server",
    "@modelcontextprotocol/core",
}

_PY_SUFFIXES = {".py"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")
_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,2}")


@dataclass(slots=True, frozen=True)
class ArtifactFingerprint:
    """Mirrors transport.revision.Fingerprint: same features type, weaker claim."""

    features: FeatureSet
    sdk_version: str | None
    claim: Claim

    @property
    def is_unknown(self) -> bool:
        return not self.features and self.sdk_version is None


def _bare_version(spec: str) -> str | None:
    match = _VERSION_RE.search(spec)
    return match.group(0) if match else None


def _pin_from_requirement(requirement: str, names: set[str]) -> str | None:
    match = _REQ_NAME_RE.match(requirement.strip())
    if match is None:
        return None
    normalized = match.group(1).lower().replace("_", "-")
    if normalized not in {n.lower().replace("_", "-") for n in names}:
        return None
    return _bare_version(requirement[match.end() :])


def _pin_from_pyproject(pyproject: Path) -> str | None:
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, OSError):
        return None
    project = data.get("project")
    deps = project.get("dependencies") if isinstance(project, dict) else None
    if not isinstance(deps, list):
        return None
    for dep in deps:
        pin = _pin_from_requirement(str(dep), _PY_SDK_NAMES)
        if pin is not None:
            return pin
    return None


def _pin_from_requirements_txt(requirements: Path) -> str | None:
    try:
        text = requirements.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pin = _pin_from_requirement(line, _PY_SDK_NAMES)
        if pin is not None:
            return pin
    return None


def _pin_from_package_json(package_json: Path) -> str | None:
    try:
        data = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
    except (ValueError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name in _JS_SDK_NAMES:
            spec = deps.get(name)
            if isinstance(spec, str):
                pin = _bare_version(spec)
                if pin is not None:
                    return pin
    return None


def detect_sdk_pin(root: Path) -> str | None:
    """Pinned MCP SDK version, from pyproject.toml / requirements.txt / package.json.

    Returns the bare version string (e.g. "2.1.0"), never the full requirement
    specifier - callers compare it against SDK_FLOOR, which is keyed the same way.
    """
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        pin = _pin_from_pyproject(pyproject)
        if pin is not None:
            return pin

    requirements = root / "requirements.txt"
    if requirements.is_file():
        pin = _pin_from_requirements_txt(requirements)
        if pin is not None:
            return pin

    package_json = root / "package.json"
    if package_json.is_file():
        pin = _pin_from_package_json(package_json)
        if pin is not None:
            return pin

    return None


def _ecosystem_of(root: Path) -> Ecosystem | None:
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        return Ecosystem.PYPI
    if (root / "package.json").is_file():
        return Ecosystem.NPM
    return None


def _source_files(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    suffixes = _PY_SUFFIXES | _JS_SUFFIXES
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in suffixes:
            yield path


def _source_features(root: Path) -> set[Feature]:
    found: set[Feature] = set()
    for path in _source_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix in _PY_SUFFIXES:
            try:
                ast.parse(text)  # parse-only: proves it is source, never runs it
            except SyntaxError:
                continue
        for feature, pattern in SOURCE_SIGNALS.items():
            if pattern.search(text):
                found.add(feature)
    return found


def _apply_sdk_floor(
    observed: set[Feature], pin: str | None, root: Path
) -> tuple[set[Feature], set[Feature]]:
    """Split `observed` into (kept, dropped) against SDK_FLOOR.

    A feature is dropped only when there is a floor to compare against and the
    pin is both parseable and strictly below it. No pin, no floor entry, or an
    unparseable version all mean "cannot rule it out" - the source evidence
    stands.
    """
    if pin is None:
        return set(observed), set()
    try:
        pin_version = Version(pin)
    except InvalidVersion:
        return set(observed), set()

    ecosystem = _ecosystem_of(root)
    kept: set[Feature] = set()
    dropped: set[Feature] = set()
    for feature in observed:
        floor = SDK_FLOOR.get(feature, {}).get(ecosystem) if ecosystem is not None else None
        if floor is None:
            kept.add(feature)
            continue
        try:
            floor_version = Version(floor)
        except InvalidVersion:
            kept.add(feature)
            continue
        if pin_version < floor_version:
            dropped.add(feature)
        else:
            kept.add(feature)
    return kept, dropped


def _claim(value: object, caveat: str | None) -> Claim:
    return Claim(
        value=value,
        method=Method.DETERMINISTIC,
        derivation=Derivation.ARTIFACT,
        confidence=ARTIFACT_CONFIDENCE,
        observed_at=datetime.now(UTC),
        caveat=caveat,
    )


def detect_features(root: Path) -> ArtifactFingerprint:
    """Derive an ArtifactFingerprint from an extracted package tree at `root`.

    `root` is expected to be the output of census.artifacts.fetch_artifact -
    already downloaded, size-capped and safely extracted. This function only
    reads text from it; it never imports, compiles, or runs anything found there.
    """
    pin = detect_sdk_pin(root)
    observed = _source_features(root)
    if pin is None and not observed:
        return ArtifactFingerprint(
            features=frozenset(),
            sdk_version=None,
            claim=_claim(None, "no SDK pin and no parseable source in the published artifact"),
        )

    kept, dropped = _apply_sdk_floor(observed, pin, root)
    caveat = None
    if dropped:
        names = ", ".join(sorted(f.value for f in dropped))
        caveat = f"source mentions {names} but the sdk pin ({pin}) predates it; sdk pin wins"
    features = frozenset(kept)
    return ArtifactFingerprint(
        features=features,
        sdk_version=pin,
        claim=_claim(sorted(f.value for f in features), caveat),
    )
