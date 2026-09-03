"""Fingerprint which MCP revision a server claims, and which features it has.

There is no handshake to negotiate in 2026-07-28: `initialize` was removed and
`server/discover` is mandatory. So this does not negotiate — it observes, and
it observes the claim and the behaviour separately, on purpose.

Observe or abstain. A feature is only ever added to the observed FeatureSet
when this module actually saw evidence of it — never because a revision was
claimed, and never because some other feature happened to be present. `MRTR`
and `SUBSCRIPTIONS_LISTEN` cannot be observed passively (the first needs a
multi-step probe, the second an open stream) and are never granted here; a
check requiring either skips with `FEATURE_ABSENT`, which is the honest
outcome. `SESSION_HEADER` is an HTTP-transport property with no channel to
observe it through the generic `Transport` protocol used here, so it too is
never granted — not even over stdio, and not over HTTP either until a
transport exposes response headers to this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.feature import Feature, FeatureSet, Revision
from agent_perimeter.transport.base import Transport, TransportError

# Widely-deployed revisions this scanner has no Revision member for. Naming
# them lets an unparseable claim carry an honest, specific caveat instead of
# the generic "no response at all" one (revision §2.2).
KNOWN_OLDER_REVISIONS = ("2025-06-18", "2025-03-26")

# A live probe observed the running server answer. It is the strongest evidence
# this tool produces, and every other derivation is calibrated below it.
LIVE_PROBE_CONFIDENCE = 0.95

# The only features fingerprint() can ever add to a Fingerprint's features set
# -- everything _claimed_revision and _observed_features actually grant below.
# MRTR and SUBSCRIPTIONS_LISTEN need an active multi-step probe or an open
# stream; SESSION_HEADER, SSE_RESUMABILITY and SUBSCRIBE_UNSUBSCRIBE have no
# passive channel through the generic Transport protocol used here. A check
# that diffs a revision's full bundle against real fingerprint() output must
# restrict itself to this set, or it reports every server as permanently
# non-conformant in five features nothing can ever observe.
PASSIVELY_OBSERVABLE_FEATURES: frozenset[Feature] = frozenset(
    {
        Feature.SERVER_DISCOVER,
        Feature.EXTENSIONS,
        Feature.INITIALIZE_HANDSHAKE,
        Feature.RESULT_TYPE,
        Feature.CACHEABLE_RESULT,
        Feature.PARAM_HEADERS,
    }
)


@dataclass(frozen=True)
class Fingerprint:
    revision_claimed: Revision | None
    features: FeatureSet
    claim: Claim
    protocol_versions_advertised: tuple[str, ...] = ()
    """The full `protocolVersions` (or single `protocolVersion`) the server
    sent, whether or not any entry parsed to a known `Revision`."""
    discover_error_code: int | None = None
    """The JSON-RPC error code observed when `server/discover` failed, if
    any. Week 2's `revision.error_code_conformance` is built on this field."""


def _highest_known(versions: tuple[str, ...]) -> Revision | None:
    """The highest *known* advertised revision, not the first — a server
    advertising both must not be recorded as the older one (revision §2.2).
    """
    known_values = {r.value for r in Revision}
    known = [Revision(v) for v in versions if v in known_values]
    return max(known) if known else None


def _revision_caveat(
    versions: tuple[str, ...], *, discover_answered: bool, initialize_answered: bool
) -> str | None:
    if not versions:
        if discover_answered or initialize_answered:
            return "Server answered but sent no parseable protocol version."
        return "Server answered neither server/discover nor initialize."
    older = [v for v in versions if v in KNOWN_OLDER_REVISIONS]
    if older:
        known = ", ".join(r.value for r in Revision)
        return (
            f"Server claims protocol revision {older[0]!r}, which predates "
            f"the revisions this scanner recognises ({known})."
        )
    return f"Server claims an unrecognised protocol revision: {list(versions)!r}."


def _claimed_revision(
    transport: Transport,
) -> tuple[Revision | None, set[Feature], tuple[str, ...], int | None]:
    """Try server/discover, falling back to initialize.

    Returns (revision, observed_features, advertised_versions,
    discover_error_code).
    """
    observed: set[Feature] = set()
    discover_error_code: int | None = None

    try:
        discover: dict[str, object] | None = transport.request("server/discover")
    except TransportError as exc:
        discover = None
        discover_error_code = exc.code

    if discover is not None:
        observed.add(Feature.SERVER_DISCOVER)
        capabilities = discover.get("capabilities")
        if isinstance(capabilities, dict) and "extensions" in capabilities:
            observed.add(Feature.EXTENSIONS)
        versions_raw = discover.get("protocolVersions")
        versions = tuple(str(v) for v in versions_raw) if isinstance(versions_raw, list) else ()
        return _highest_known(versions), observed, versions, discover_error_code

    try:
        initialized = transport.request("initialize")
    except TransportError:
        return None, observed, (), discover_error_code

    observed.add(Feature.INITIALIZE_HANDSHAKE)
    version = initialized.get("protocolVersion")
    versions = (str(version),) if version is not None else ()
    return _highest_known(versions), observed, versions, discover_error_code


def _contains_header_annotation(node: object) -> bool:
    """Whether an x-mcp-header annotation exists anywhere under this node,
    reachable by a plain properties chain or not. PARAM_HEADERS means the
    server uses the annotation mechanism at all; whether a given occurrence
    is reachable is a separate finding (revision.header_annotation_unreachable
    -- checks/revision/_header_annotations.py's own recursive walk), not
    something this presence check should presuppose. A shallow, top-level-only
    check would mean the one shape that check exists to catch could never
    satisfy its own requires_features={PARAM_HEADERS} gate."""
    if not isinstance(node, dict):
        return False
    if "x-mcp-header" in node:
        return True
    for value in node.values():
        if isinstance(value, dict) and _contains_header_annotation(value):
            return True
        if isinstance(value, list):
            for item in value:
                if _contains_header_annotation(item):
                    return True
    return False


def _has_header_annotation(tool: object) -> bool:
    """PARAM_HEADERS is observed, not inferred: does any parameter's own
    schema carry an `x-mcp-header` annotation anywhere in its structure
    (its value the header-name suffix)? A property merely *named*
    `x-mcp-header` does not count."""
    if not isinstance(tool, dict):
        return False
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    return any(_contains_header_annotation(prop_schema) for prop_schema in properties.values())


def _observed_features(transport: Transport) -> set[Feature]:
    observed: set[Feature] = set()
    try:
        listing = transport.request("tools/list")
    except TransportError:
        return observed

    if "resultType" in listing:
        observed.add(Feature.RESULT_TYPE)
    if "ttlMs" in listing or "cacheScope" in listing:
        observed.add(Feature.CACHEABLE_RESULT)

    tools = listing.get("tools")
    if isinstance(tools, list) and any(_has_header_annotation(tool) for tool in tools):
        observed.add(Feature.PARAM_HEADERS)

    return observed


def fingerprint(transport: Transport) -> Fingerprint:
    """Establish the claimed revision and the observed features, independently."""
    claimed, from_claim, versions, discover_error_code = _claimed_revision(transport)
    features = from_claim | _observed_features(transport)

    caveat = None
    if claimed is None:
        caveat = _revision_caveat(
            versions,
            discover_answered=Feature.SERVER_DISCOVER in features,
            initialize_answered=Feature.INITIALIZE_HANDSHAKE in features,
        )

    claim = Claim(
        value=claimed.value if claimed is not None else None,
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        confidence=LIVE_PROBE_CONFIDENCE,
        observed_at=datetime.now(UTC),
        caveat=caveat,
    )
    return Fingerprint(
        revision_claimed=claimed,
        features=frozenset(features),
        claim=claim,
        protocol_versions_advertised=versions,
        discover_error_code=discover_error_code,
    )
