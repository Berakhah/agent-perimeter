"""Run the full check suite against one corpus case, in-process.

Local fixture-corpus cases fingerprint and enumerate the real in-process
fixture (tests/fixtures/servers/server.py, Week 1 Task 6's
handle(message: dict) -> dict), selected by revision/flaw, exactly as a live
scan would -- the real fingerprint(transport) (Week 1 Task 8), not a canned
Fingerprint(features=BUNDLES[revision]) that made conformance_mismatch
compute an empty diff and never fire (revision §4.3). Each case's
ScanContext carries a scope that authorises probing that case's own fixture,
so the four active probes and injection.path_proof are actually measured
instead of always skipping as unauthorised (revision §4.4).

MCPTox cases carry no fixture behind them -- the sample's tool_name and
description *are* the thing under test -- so they are checked directly
against that content (mcptox.sample_tool) rather than dispatched to the
shared fixture.

Everything here runs in-process, through the fixture's own handle() function,
never through a subprocess or a container. One container per request would be
~51 launches for the 17-case local corpus and ~4,000 for MCPTox -- not
runnable in CI (revision §7.1). A live scan still goes through the real
containerised transport; only this eval harness takes the fast path.
"""

from __future__ import annotations

import importlib.util
import itertools
import os
from datetime import UTC, date, datetime
from pathlib import Path
from types import ModuleType

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.checks.all_checks import ALL_CHECKS
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.registry import BaselineStatus, applicable
from agent_perimeter.discover.enumerate import enumerate_tools
from agent_perimeter.drift.compare import compare_tools
from agent_perimeter.eval.corpus import CorpusCase
from agent_perimeter.eval.mcptox import sample_tool
from agent_perimeter.model.drift import DriftEvent
from agent_perimeter.model.feature import BUNDLES, Revision
from agent_perimeter.model.scope import ScopeFile
from agent_perimeter.model.snapshot import ToolSnapshot
from agent_perimeter.transport.base import TransportError, _reject_header_override
from agent_perimeter.transport.revision import Fingerprint, fingerprint

FIXTURE_SERVER = Path(__file__).parents[2] / "tests" / "fixtures" / "servers" / "server.py"

_LOAD_COUNTER = itertools.count()

# secrets.config_scan reads context.raw["_config"] -- local client configuration,
# never something an RPC method returns -- so nothing in the transport loop
# below can ever populate it. These two flaws inject it directly, the same
# way cli.py populates it from an operator-supplied --config file.
_CONFIG_FLAWS: dict[str, dict[str, object]] = {
    "config_secret": {"env": {"API_KEY": "sk-test-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"}},
    "config_placeholder": {"env": {"API_KEY": "changeme"}},
}

# An MCPTox sample has no live server to fingerprint, so there is nothing to
# *observe* Feature-by-feature the way the real fingerprinter does. There is
# also no `Feature.STATELESS_META` any more (see model/feature.py's
# docstring: that member described the client's request shape, not something
# a server does, and was removed). The faithful replacement for "treat this
# as a conformant modern server" is the full feature bundle a real
# 2026-07-28 server would expose -- BUNDLES[Revision.R2026_07_28] -- not the
# empty set. Emptiness would make revision.conformance_mismatch (which has
# no feature gate of its own -- it runs unconditionally) compute
# BUNDLES[claimed] - features() = the *entire* bundle and fire a false
# "missing every 2026-07-28 feature" finding on every single MCPTox sample,
# which is exactly the false-positive noise this function exists to avoid.
# The full bundle makes that diff empty, so conformance_mismatch is silent,
# and the six other feature-gated checks in ALL_CHECKS (cache_scope,
# deprecated_features, the three header_annotation_* checks,
# request_state_binding) become applicable but find nothing to report
# against an MCPTox sample's empty raw/schema -- verified empirically, see
# task-11-report.md.
_MCPTOX_FEATURES = BUNDLES[Revision.R2026_07_28]


def fixture_scope(target: str) -> ScopeFile:
    """Authorise probing this session's own in-process fixture for `target`.

    Authorising probing of a fixture this project owns is exactly what a
    scope file is for. Dates are relative to today so a scan run months from
    now in CI is never refused for having "expired".
    """
    today = date.today()
    return ScopeFile(
        target=target,
        authorising_party="Agent Perimeter eval harness (own fixture)",
        authorised_on=today,
        expires_on=today,
        attestation=(
            "Authorises active probing of the project's own in-process "
            "fixture, for evaluation only."
        ),
    )


class InProcessTransport:
    """Adapts the fixture's handle() to the Transport protocol without a
    subprocess or a container. Eval-only: a live scan never uses this."""

    def __init__(self, revision: str, flaw: str) -> None:
        self._module = _load_fixture(revision, flaw)

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        # Same fail-closed boundary stdio.py and legacy_sse.py use: this
        # transport has no header channel to diverge from the body, and
        # handle() ignores unknown params rather than rejecting them, so
        # forwarding this probe param unrejected would make
        # revision.header_body_mismatch misread "unknown param silently
        # ignored" as "server honoured the mismatched body" -- a false
        # positive on every case (see transport/base.py's own docstring).
        _reject_header_override(self, params)
        message: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": next(_LOAD_COUNTER),
            "method": method,
        }
        if params is not None:
            message["params"] = params
        reply = self._module.handle(message)
        if "error" in reply:
            raise TransportError(str(reply["error"]))
        result = reply.get("result")
        return result if isinstance(result, dict) else {}

    def close(self) -> None:
        pass


def _load_fixture(revision: str, flaw: str) -> ModuleType:
    """A fresh module per case: the fixture reads REVISION/FLAW from the
    environment at import time, so each case needs its own module object
    with its own env snapshot -- the same pattern the fixture's own
    self-test uses."""
    os.environ["AP_FIXTURE_REVISION"] = revision
    os.environ["AP_FIXTURE_FLAW"] = flaw
    spec = importlib.util.spec_from_file_location(
        f"ap_eval_fixture_{next(_LOAD_COUNTER)}", FIXTURE_SERVER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load fixture spec from {FIXTURE_SERVER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _NoTransport:
    """An MCPTox sample has no live server behind it -- nothing should ever
    call the transport while checking one."""

    def request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        msg = f"MCPTox sample check unexpectedly called transport.request({method!r})"
        raise TransportError(msg)

    def close(self) -> None:
        pass


def _fingerprint_for_sample() -> Fingerprint:
    """An MCPTox sample has no live server to fingerprint -- treat it as a
    conformant modern server so description/schema checks are not skipped
    for a revision mismatch that has nothing to do with what is under test."""
    return Fingerprint(
        revision_claimed=Revision.R2026_07_28,
        features=_MCPTOX_FEATURES,
        claim=Claim(
            value="2026-07-28",
            method=Method.DETERMINISTIC,
            derivation=Derivation.PROBE,
            observed_at=datetime.now(UTC),
        ),
    )


def _run(
    context: ScanContext,
    *,
    models_available: bool,
    baseline_status: BaselineStatus = BaselineStatus.NONE_ON_RECORD,
) -> set[str]:
    runnable, _ = applicable(
        ALL_CHECKS,
        context.fingerprint.features,
        scope=context.scope,
        target=context.target,
        today=date.today(),
        models_available=models_available,
        baseline_status=baseline_status,
    )
    return {check.id for check in runnable if check.run(context)}


def run_case(case: CorpusCase, *, models_available: bool = False) -> set[str]:
    """Run the full check suite against one corpus case and return the ids
    of checks that fired."""
    tool = sample_tool(case.id)
    if tool is not None:
        context = ScanContext(
            target=case.id,
            transport=_NoTransport(),
            fingerprint=_fingerprint_for_sample(),
            tools=[tool],
        )
        return _run(context, models_available=models_available)

    transport = InProcessTransport(case.revision, case.flaw)
    target = f"fixture:{case.id}"
    scope = fixture_scope(target)

    raw: dict[str, dict[str, object]] = {}
    for method in ("server/discover", "tools/list"):
        try:
            raw[method] = transport.request(method)
        except TransportError:  # a fixture revision that will not answer is data
            continue
    if case.flaw in _CONFIG_FLAWS:
        raw["_config"] = _CONFIG_FLAWS[case.flaw]

    now = datetime.now(UTC)
    tools = enumerate_tools(transport)
    baseline: ToolSnapshot | None = None
    drift_events: tuple[DriftEvent, ...] = ()
    if case.baseline_flaw is not None:
        baseline_transport = InProcessTransport(case.revision, case.baseline_flaw)
        baseline = ToolSnapshot.from_tools(
            target, enumerate_tools(baseline_transport), taken_at=now
        )
        drift_events = compare_tools(baseline, target, tools, now=now)

    context = ScanContext(
        target=target,
        transport=transport,
        fingerprint=fingerprint(transport),
        tools=tools,
        scope=scope,
        raw=raw,
        baseline=baseline,
        drift_events=drift_events,
    )
    return _run(
        context,
        models_available=models_available,
        baseline_status=(
            BaselineStatus.PRESENT if baseline is not None else BaselineStatus.NONE_ON_RECORD
        ),
    )
