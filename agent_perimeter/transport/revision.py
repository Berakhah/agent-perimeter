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


def _has_header_annotation(tool: object) -> bool:
    """PARAM_HEADERS is observed, not inferred: does any parameter's own
    schema carry an `x-mcp-header` annotation (its value the header-name
    suffix)? A property merely *named* `x-mcp-header` does not count."""
    if not isinstance(tool, dict):
        return False
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    return any(
        isinstance(prop_schema, dict) and "x-mcp-header" in prop_schema
        for prop_schema in properties.values()
    )


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
