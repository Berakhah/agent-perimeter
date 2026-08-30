# tests/model/test_feature.py
from agent_perimeter.model.feature import BUNDLES, Feature, Revision


def test_modern_revision_has_discover_and_lacks_handshake() -> None:
    modern = BUNDLES[Revision.R2026_07_28]
    assert Feature.SERVER_DISCOVER in modern
    assert Feature.RESULT_TYPE in modern
    assert Feature.CACHEABLE_RESULT in modern
    assert Feature.MRTR in modern
    assert Feature.INITIALIZE_HANDSHAKE not in modern
    assert Feature.SESSION_HEADER not in modern


def test_legacy_revision_has_handshake_and_lacks_discover() -> None:
    legacy = BUNDLES[Revision.R2025_11_25]
    assert Feature.INITIALIZE_HANDSHAKE in legacy
    assert Feature.SESSION_HEADER in legacy
    assert Feature.SERVER_DISCOVER not in legacy


def test_every_revision_bundle_is_a_frozenset() -> None:
    assert all(isinstance(bundle, frozenset) for bundle in BUNDLES.values())
