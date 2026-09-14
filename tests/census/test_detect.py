import json
from pathlib import Path

from agent_perimeter._contracts import Derivation
from agent_perimeter.census import detect
from agent_perimeter.census.detect import (
    ARTIFACT_CONFIDENCE,
    detect_features,
    detect_sdk_pin,
)
from agent_perimeter.model.census import Ecosystem
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


# --- Beyond the brief's 7: exercise both branches of the disagreement rule and
# the JS token-scan path, so py_new/js_new are not fixtures nothing runs against.


def test_a_modern_sdk_pin_does_not_drop_the_features_it_supports() -> None:
    """The mirror of the py_old case: source evidence that the pin *does* clear
    is kept, not just dropped evidence being the only thing under test."""
    fp = detect_features(FIXTURES / "py_new")
    assert Feature.SERVER_DISCOVER in fp.features
    assert Feature.RESULT_TYPE in fp.features
    assert "sdk pin" not in (fp.claim.caveat or "")


def test_a_javascript_artifact_is_detected_via_token_scan() -> None:
    """Detection is by ast parse for Python and a token scan for JavaScript -
    this exercises the JS half, which none of the brief's 7 tests touch."""
    fp = detect_features(FIXTURES / "js_new")
    assert fp.sdk_version == "2.1.0"
    assert Feature.RESULT_TYPE in fp.features
    assert Feature.CACHEABLE_RESULT in fp.features


def test_a_v2_split_package_pin_is_recognised_not_just_the_v1_monolith() -> None:
    """@modelcontextprotocol/sdk (v1) never shipped a 2.x release - it is
    frozen at 1.30.0. v2 split the SDK into @modelcontextprotocol/server et
    al, which is what a real server artifact pins. A package.json naming
    only the new package must still be read as a valid, above-floor pin."""
    assert detect_sdk_pin(FIXTURES / "js_v2_split") == "2.1.0"
    fp = detect_features(FIXTURES / "js_v2_split")
    assert fp.sdk_version == "2.1.0"
    assert Feature.RESULT_TYPE in fp.features
    assert Feature.CACHEABLE_RESULT in fp.features
    assert "sdk pin" not in (fp.claim.caveat or "")


# --- Task 8: real npm/PyPI artifacts keep manifests one directory down, not
# at the extraction root; the first full census run misclassified 94% of
# artifacts "unknown" because of this.


def test_npm_pin_is_found_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "^1.12.0"}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.12.0"


def test_pypi_pin_is_found_in_a_versioned_sdist_directory(tmp_path: Path) -> None:
    d = tmp_path / "mcp_server_x-2026.8.18"
    d.mkdir()
    (d / "pyproject.toml").write_text(
        '[project]\ndependencies = ["mcp>=1.2.0"]\n', encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "1.2.0"


def test_pypi_pin_is_read_from_sdist_pkg_info(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text(
        "Name: x\nRequires-Dist: httpx\nRequires-Dist: mcp>=2.1\n", encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "2.1"


def test_pypi_pin_is_read_from_wheel_metadata(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_text(
        'Name: x\nRequires-Dist: mcp>=2.0.0; python_version >= "3.10"\n', encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) == "2.0.0"


def test_environment_marker_version_is_not_mistaken_for_the_pin(tmp_path: Path) -> None:
    d = tmp_path / "x-1.0"
    d.mkdir()
    (d / "PKG-INFO").write_text('Requires-Dist: mcp; python_version >= "3.10"\n', encoding="utf-8")
    assert detect.detect_sdk_pin(tmp_path) is None


def test_manifest_search_is_one_level_deep_only(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}), encoding="utf-8"
    )
    assert detect.detect_sdk_pin(tmp_path) is None


def test_ecosystem_is_detected_under_the_package_directory(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "package.json").write_text("{}", encoding="utf-8")
    assert detect._ecosystem_of(tmp_path) is Ecosystem.NPM
