### Task 4: Feature detection from artifacts

**Files:**
- Create: `agent_perimeter/census/detect.py`
- Modify: `agent_perimeter/transport/revision.py` (add `LIVE_PROBE_CONFIDENCE`)
- Test: `tests/census/test_detect.py`
- Test fixture: `tests/fixtures/artifacts/py_new/`, `tests/fixtures/artifacts/py_old/`, `tests/fixtures/artifacts/js_new/`, `tests/fixtures/artifacts/empty/`

**Interfaces:**
- Produces: `ARTIFACT_CONFIDENCE`; `SDK_FLOOR` (SDK version at which each `Feature` became available); `ArtifactFingerprint(features, sdk_version, claim)`; `detect_sdk_pin(root) -> str | None`; `detect_features(root) -> ArtifactFingerprint`.
- Consumes: `Feature`, `FeatureSet` (= `frozenset[Feature]`, Week 1 Task 7); `Claim`, `Method`, `Derivation` (Week 1 Task 2 `_contracts.py`); `Fingerprint` (Week 1 Task 8).

**Shape note:** Week 1 made `FeatureSet` a plain `frozenset[Feature]` and put provenance on the `Claim`, not on the feature set. This task follows that, returning an `ArtifactFingerprint` that mirrors Week 1's `Fingerprint` — same two fields plus the SDK pin — so the live path and the artifact path stay structurally parallel and the report can compare them without a translation layer.

This is the module the headline claim rests on. Two independent signals must agree before a feature is asserted: the **pinned SDK version** (a package pinned to an SDK predating `2026-07-28` cannot serve that revision, regardless of what its source says) and a **source scan** for the handlers the revision requires. Where the two disagree, the lower wins and a caveat is attached — a claim that hedges is worth more than a claim that is wrong.

Detection is by `ast` parse for Python and a token scan for JavaScript. **No import, no execution, no `eval`.**

- [ ] **Step 1: RED — the confidence ordering and the disagreement rule**

Create `tests/census/test_detect.py`:

```python
from pathlib import Path

from agent_perimeter._contracts import Derivation
from agent_perimeter.census.detect import (
    ARTIFACT_CONFIDENCE,
    detect_features,
    detect_sdk_pin,
)
from agent_perimeter.model.feature import Feature
from agent_perimeter.transport.revision import LIVE_PROBE_CONFIDENCE

FIXTURES = Path("tests/fixtures/artifacts")


def test_artifact_confidence_is_strictly_below_a_live_probe() -> None:
    """An artifact says what a package could do, not what a deployment does."""
    assert ARTIFACT_CONFIDENCE < LIVE_PROBE_CONFIDENCE


def test_a_modern_sdk_pin_is_read_from_pyproject() -> None:
    assert detect_sdk_pin(FIXTURES / "py_new") == "2.1.0"


def test_an_old_sdk_pin_bounds_the_feature_set_regardless_of_source() -> None:
    """Source mentioning server/discover cannot raise a package pinned below it."""
    fp = detect_features(FIXTURES / "py_old")
    assert Feature.SERVER_DISCOVER not in fp.features
    assert "sdk pin" in (fp.claim.caveat or "")


def test_every_artifact_derived_claim_is_marked_as_such() -> None:
    fp = detect_features(FIXTURES / "py_new")
    assert fp.claim.derivation is Derivation.ARTIFACT
    assert fp.claim.confidence == ARTIFACT_CONFIDENCE


def test_unresolvable_coordinates_yield_unknown_not_absent() -> None:
    """No SDK pin and no parseable source is UNKNOWN, never 'does not support'."""
    fp = detect_features(FIXTURES / "empty")
    assert fp.is_unknown
    assert fp.features == frozenset()
    assert fp.claim.caveat


def test_the_features_type_matches_the_live_path() -> None:
    """Same type as transport.revision.Fingerprint.features, so they compare directly."""
    fp = detect_features(FIXTURES / "py_new")
    assert isinstance(fp.features, frozenset)


def test_detection_never_imports_the_artifact() -> None:
    src = Path("agent_perimeter/census/detect.py").read_text()
    for forbidden in ("importlib", "exec(", "eval(", "subprocess", "__import__"):
        assert forbidden not in src
```

Run: `uv run pytest tests/census/test_detect.py`
Expected: `ModuleNotFoundError: agent_perimeter.census.detect`

- [ ] **Step 2: GREEN — the detector**

Create `agent_perimeter/census/detect.py`:

First add the constant the ordering test compares against, to `agent_perimeter/transport/revision.py`:

```python
# A live probe observed the running server answer. It is the strongest evidence
# this tool produces, and every other derivation is calibrated below it.
LIVE_PROBE_CONFIDENCE = 0.95
```

Then create `agent_perimeter/census/detect.py`:

```python
"""Derive a FeatureSet from a published artifact. Parse only; never execute."""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packaging.version import InvalidVersion, Version

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.feature import Feature, FeatureSet

# Strictly below transport.revision.LIVE_PROBE_CONFIDENCE. An artifact tells you
# what a package could do, not what a deployment does.
ARTIFACT_CONFIDENCE = 0.6

# Lowest SDK release that can serve each feature. Below the floor, source evidence
# is discarded: a package cannot serve what its pinned dependency cannot express.
SDK_FLOOR: dict[Feature, dict[str, str]] = {
    Feature.SERVER_DISCOVER: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.RESULT_TYPE: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.CACHEABLE_RESULT: {"pypi": "2.0.0", "npm": "2.0.0"},
    Feature.MRTR: {"pypi": "2.0.0", "npm": "2.0.0"},
}

SOURCE_SIGNALS: dict[Feature, re.Pattern[str]] = {
    Feature.SERVER_DISCOVER: re.compile(r"""["']server/discover["']"""),
    Feature.RESULT_TYPE: re.compile(r"\bresultType\b|\bresult_type\b"),
    Feature.CACHEABLE_RESULT: re.compile(r"\bttlMs\b|\bcacheScope\b|\bcache_scope\b"),
    Feature.MRTR: re.compile(r"\bInputRequiredResult\b|\binputResponses\b"),
    Feature.X_MCP_HEADER: re.compile(r"\bx-mcp-header\b", re.I),
}

_PY_SDK_NAMES = {"mcp", "modelcontextprotocol"}
_JS_SDK_NAMES = {"@modelcontextprotocol/sdk"}


@dataclass(slots=True, frozen=True)
class ArtifactFingerprint:
    """Mirrors transport.revision.Fingerprint. Same features type, weaker claim."""

    features: FeatureSet
    sdk_version: str | None
    claim: Claim

    @property
    def is_unknown(self) -> bool:
        return not self.features and self.sdk_version is None


def detect_sdk_pin(root: Path) -> str | None:
    """Pinned MCP SDK version, from pyproject / requirements / package.json."""
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
        deps = (data.get("project") or {}).get("dependencies") or []
        for dep in deps:
            if (pin := _pin_from_requirement(str(dep), _PY_SDK_NAMES)) is not None:
                return pin
    ...  # requirements.txt, then package.json dependencies
    return None


def _source_features(root: Path) -> set[Feature]:
    found: set[Feature] = set()
    for path in _source_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            try:
                ast.parse(text)  # parse-only: proves it is source, never runs it
            except SyntaxError:
                continue
        for feature, pattern in SOURCE_SIGNALS.items():
            if pattern.search(text):
                found.add(feature)
    return found


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
    pin = detect_sdk_pin(root)
    observed = _source_features(root)
    if pin is None and not observed:
        return ArtifactFingerprint(
            features=frozenset(),
            sdk_version=None,
            claim=_claim(None, "no SDK pin and no parseable source in the published artifact"),
        )

    bounded, dropped = _apply_sdk_floor(observed, pin, root)
    caveat = None
    if dropped:
        names = ", ".join(sorted(f.value for f in dropped))
        caveat = f"source mentions {names} but the sdk pin ({pin}) predates it; sdk pin wins"
    features = frozenset(bounded)
    return ArtifactFingerprint(
        features=features,
        sdk_version=pin,
        claim=_claim(sorted(f.value for f in features), caveat),
    )
```

- [ ] **Step 3: REFACTOR — record the floor's basis, not just its value**

`SDK_FLOOR` is a claim about someone else's release history. Add above it:

```python
# Verified against the SDK changelogs on the collection date and recorded in
# docs/methodology.md under "SDK version floors". If a floor is wrong, every
# artifact-derived number moves — so it is cited, not assumed.
```

Then add the `## SDK version floors` table to `docs/methodology.md`: feature, ecosystem, floor version, release date, changelog URL, date checked.

- [ ] **Step 4: Verify against the fixtures**

Run: `uv run pytest tests/census/ -v`
Expected: all pass, including the disagreement rule and the unknown case.

- [ ] **Step 5: Commit**

```bash
uv run ruff check . && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/detect.py agent_perimeter/transport/revision.py \
        tests/census/ tests/fixtures/artifacts/ docs/methodology.md
git commit -m "feat: artifact feature detection bounded by the pinned SDK version"
```

---

