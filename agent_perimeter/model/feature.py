# agent_perimeter/model/feature.py
"""Protocol features, and the revision bundles that name sets of them.

Checks are predicated on observed features, never on a claimed version string,
so a server that implements a revision partially is handled correctly rather
than mis-scanned.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml

FEATURES_YAML = Path(__file__).parents[1] / "transport" / "features.yaml"


class Feature(StrEnum):
    """No `STATELESS_META` member: that would describe the *client's*
    request shape, not something the server does — a version-implies-feature
    proxy this design otherwise avoids. See revision §2.1."""

    SERVER_DISCOVER = "server_discover"
    RESULT_TYPE = "result_type"
    CACHEABLE_RESULT = "cacheable_result"
    MRTR = "mrtr"
    PARAM_HEADERS = "param_headers"
    SUBSCRIPTIONS_LISTEN = "subscriptions_listen"
    EXTENSIONS = "extensions"
    INITIALIZE_HANDSHAKE = "initialize_handshake"
    SESSION_HEADER = "session_header"
    SSE_RESUMABILITY = "sse_resumability"
    SUBSCRIBE_UNSUBSCRIBE = "subscribe_unsubscribe"


class Revision(StrEnum):
    R2025_11_25 = "2025-11-25"
    R2026_07_28 = "2026-07-28"


FeatureSet = frozenset[Feature]


def load_bundles(path: Path = FEATURES_YAML) -> dict[Revision, FeatureSet]:
    raw: dict[str, list[str]] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        Revision(str(revision)): frozenset(Feature(name) for name in names)
        for revision, names in raw.items()
    }


BUNDLES: dict[Revision, FeatureSet] = load_bundles()
