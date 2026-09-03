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
