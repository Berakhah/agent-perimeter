"""Derive a FeatureSet from a published artifact's source. Never run it.

Two independent signals must both be present before a feature is asserted:
the pinned MCP SDK version (a package pinned to an SDK release predating the
2026-07-28 revision cannot serve it, regardless of what its own source says)
and a scan of the source for the handlers that revision requires. Where the
two disagree, the lower wins and a caveat is attached; where the artifact
pins no SDK at all, source evidence for any floor-gated feature is dropped
and the artifact is reported unknown - a claim that hedges is worth more
than a claim that is wrong.

The pin recorded is the *lowest lower bound* of the requirement, never a
cap: `mcp<2.0.0,>=1.9.0` (the order setuptools writes `Requires-Dist:` in)
is 1.9.0, and `mcp<3` is no pin at all.

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

from packaging.requirements import InvalidRequirement, Requirement
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

# Specifier operators that state a lower bound. `<`, `<=` and `!=` bound from
# above (or exclude a point) and say nothing about the oldest SDK a package
# accepts, which is the only thing SDK_FLOOR compares against.
_LOWER_BOUND_OPERATORS = frozenset({">=", "==", "~=", ">", "==="})

# npm range grammar: an optional comparator followed by a version. `^`, `~`
# and a bare version are lower bounds; `<` and `<=` are caps.
_NPM_TOKEN_RE = re.compile(
    r"(>=|<=|>|<|=|\^|~)?\s*(?<![\w.-])v?(\d+(?:\.\d+){0,2})(?:[-+][0-9A-Za-z.-]*)?"
)
_NPM_CAP_OPERATORS = frozenset({"<", "<="})


@dataclass(slots=True, frozen=True)
class ArtifactFingerprint:
    """Mirrors transport.revision.Fingerprint: same features type, weaker claim."""

    features: FeatureSet
    sdk_version: str | None
    claim: Claim

    @property
    def is_unknown(self) -> bool:
        return not self.features and self.sdk_version is None


def _lowest(candidates: list[str]) -> str | None:
    """The original text of the smallest parseable version in `candidates`."""
    parsed: list[tuple[Version, str]] = []
    for text in candidates:
        try:
            parsed.append((Version(text), text))
        except InvalidVersion:
            continue
    return min(parsed)[1] if parsed else None


def _npm_lower_bound(spec: str) -> str | None:
    """Lowest version token of an npm range whose comparator is not a cap.

    `^1.12.0` -> 1.12.0, `>=1.0.0 <2.0.0` -> 1.0.0, `<2.0.0` -> None. A
    `||` union is treated as one flat token list: its lowest lower bound is
    still the oldest SDK the package accepts.
    """
    floors = [
        m.group(2) for m in _NPM_TOKEN_RE.finditer(spec) if m.group(1) not in _NPM_CAP_OPERATORS
    ]
    return _lowest(floors)


_PY_MANIFESTS = ("pyproject.toml", "requirements.txt", "PKG-INFO")


def _manifest_dirs(root: Path) -> list[Path]:
    """`root` plus its immediate subdirectories. npm tarballs extract to
    `package/`, sdists to `<name>-<version>/`; one level covers both without
    walking into vendored trees."""
    if not root.is_dir():
        return []
    return [root, *sorted(p for p in root.iterdir() if p.is_dir())]


def _pin_from_requirement(requirement: str, names: set[str]) -> str | None:
    """Lowest lower bound of a PEP 508 requirement naming one of `names`.

    `packaging` handles extras, markers and parentheses; it also normalises
    specifier order, which is exactly why the first version-looking token
    must never be taken - `>=1.9.0,<2.0.0` round-trips as `<2.0.0,>=1.9.0`.
    """
    try:
        req = Requirement(requirement)
    except InvalidRequirement:
        return None
    normalized = req.name.lower().replace("_", "-")
    if normalized not in {n.lower().replace("_", "-") for n in names}:
        return None
    floors = [s.version for s in req.specifier if s.operator in _LOWER_BOUND_OPERATORS]
    return _lowest(floors)


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
                pin = _npm_lower_bound(spec)
                if pin is not None:
                    return pin
    return None


def _pin_from_metadata(metadata: Path) -> str | None:
    """`Requires-Dist:` lines of a wheel METADATA or sdist PKG-INFO."""
    try:
        text = metadata.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Requires-Dist:"):
            pin = _pin_from_requirement(line.partition(":")[2], _PY_SDK_NAMES)
            if pin is not None:
                return pin
    return None


def detect_sdk_pin(root: Path) -> str | None:
    """Pinned MCP SDK version.

    Real artifacts don't keep manifests at the extraction root: npm tarballs
    extract to `package/`, PyPI sdists to `<name>-<version>/`, and wheels keep
    their requirements in `*.dist-info/METADATA`. Manifests are searched for
    in `root` and its immediate subdirectories (one level only).

    Returns the bare version string (e.g. "2.1.0"), never the full requirement
    specifier - callers compare it against SDK_FLOOR, which is keyed the same way.
    """
    for manifest_dir in _manifest_dirs(root):
        pyproject = manifest_dir / "pyproject.toml"
        if pyproject.is_file():
            pin = _pin_from_pyproject(pyproject)
            if pin is not None:
                return pin

        requirements = manifest_dir / "requirements.txt"
        if requirements.is_file():
            pin = _pin_from_requirements_txt(requirements)
            if pin is not None:
                return pin

        pkg_info = manifest_dir / "PKG-INFO"
        if pkg_info.is_file():
            pin = _pin_from_metadata(pkg_info)
            if pin is not None:
                return pin

        package_json = manifest_dir / "package.json"
        if package_json.is_file():
            pin = _pin_from_package_json(package_json)
            if pin is not None:
                return pin

    for meta in root.glob("*.dist-info/METADATA"):
        pin = _pin_from_metadata(meta)
        if pin is not None:
            return pin

    return None


def _ecosystem_of(root: Path) -> Ecosystem | None:
    manifest_dirs = _manifest_dirs(root)
    if any((d / name).is_file() for d in manifest_dirs for name in _PY_MANIFESTS):
        return Ecosystem.PYPI
    if next(root.glob("*.dist-info"), None) is not None:
        return Ecosystem.PYPI
    if any((d / "package.json").is_file() for d in manifest_dirs):
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

    A floor-gated feature is dropped when the pin is strictly below its floor,
    or when there is no pin at all: "supports" requires a pin at or above the
    floor AND the source signal, so an unpinned artifact cannot assert any
    feature that has a floor. Features with no floor entry (PARAM_HEADERS)
    stand on source evidence alone, and an unparseable pin is treated as
    "cannot rule it out".
    """
    if pin is None:
        kept_unpinned = {f for f in observed if f not in SDK_FLOOR}
        return kept_unpinned, set(observed) - kept_unpinned
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
        if pin is None:
            caveat = (
                f"source mentions {names} but the artifact pins no SDK; a feature cannot "
                "be asserted without a pin at or above its floor"
            )
        else:
            caveat = f"source mentions {names} but the sdk pin ({pin}) predates it; sdk pin wins"
    features = frozenset(kept)
    return ArtifactFingerprint(
        features=features,
        sdk_version=pin,
        claim=_claim(sorted(f.value for f in features), caveat),
    )
