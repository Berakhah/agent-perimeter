# agent_perimeter/scan_runner.py
"""The scan pipeline shared by the CLI and the API.

Build a transport, fingerprint it, enumerate its tools, decide which checks
apply, run them, build the capability graph. Everything except the CLI-only
extras (--repo/--config/--env-file/--agent-transcript/--only/--sarif/--html),
which have no HTTP-request equivalent and stay in cli.py, layered on this
function's result via `extra_raw`/`invocation_flags`/`checks`.

This is what makes tests/api/test_refusal.py's
test_the_api_and_the_cli_refuse_on_the_same_condition true by construction:
there is exactly one call site for require_scope on the active-mode gating
path, not two that could eventually disagree (hard constraint 1).
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from agent_perimeter.checks.all_checks import ALL_CHECKS, CheckOutcome, run_checks
from agent_perimeter.checks.base import Check
from agent_perimeter.checks.context import ScanContext
from agent_perimeter.checks.registry import Skipped, applicable
from agent_perimeter.discover.enumerate import ToolRecord, enumerate_tools
from agent_perimeter.graph.build import build_graph
from agent_perimeter.model.edge import CapabilityEdge
from agent_perimeter.model.finding import Finding
from agent_perimeter.model.scope import ScopeFile, require_scope
from agent_perimeter.transport.base import Transport, TransportError
from agent_perimeter.transport.revision import Fingerprint, fingerprint
from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

DEFAULT_CONTACT_URL = "https://github.com/Berakhah/agent-perimeter"

# Same DSN alembic.ini's `sqlalchemy.url` uses (migrations/env.py expands
# ${POSTGRES_PASSWORD}/${POSTGRES_HOST} the same way, at read time, since
# configparser/typer don't do it on their own) - one Postgres instance for
# migrations, the CLI and the API to share. Keep in sync by hand; there's no
# app-wide config module yet for either to read from. ${POSTGRES_HOST}
# defaults to `localhost` for bare-metal use (.env.example) and is set to
# `db` by docker-compose.yml's `api` service, which is on the same Docker
# network as the `db` service rather than the host's loopback interface.
DEFAULT_DATABASE_URL = "postgresql+psycopg://agent_perimeter:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:5432/agent_perimeter"


class ScanMode(StrEnum):
    """A free-form `str` let `--mode actve` (typo) silently run a passive
    scan with no warning. An enum makes Typer/pydantic reject an invalid
    value outright instead of misinterpreting it as "not active"."""

    PASSIVE = "passive"
    ACTIVE = "active"


# Ambiguity, concretely (revision §2.5): a tool whose description matched only
# a *weak* deterministic signal and no *strong* one is handed to the model
# judge for escalation; a strong signal alone is confident enough on its own.
WEAK_SIGNAL_CATEGORIES = frozenset({"model_directive", "exfiltration", "confusable_name"})
STRONG_SIGNAL_CATEGORIES = frozenset(
    {"override", "concealment", "role_claim", "bidi_override", "zero_width", "tag_character"}
)


def compute_ambiguous_tools(tools: list[ToolRecord], target: str) -> frozenset[str]:
    """Mirror the deterministic detectors exactly, or their false positives reopen.

    `target` is needed so an `exfiltration` match can be exempted the same way
    `ImperativeInjectionCheck` exempts it — sending data back to the server's
    own origin is not exfiltration. `tool.name` is scanned through
    `scan_text` too, alongside `tool.description`, because
    `UnicodeAnomalyCheck` scans both fields for strong signals (bidi/zero-
    width/tag characters) and a name-only strong signal must disqualify
    ambiguity exactly like a description one does.
    """
    from agent_perimeter.checks.descriptions.imperative_injection import (
        IMPERATIVE_PATTERNS,
        _same_origin,
    )
    from agent_perimeter.checks.descriptions.unicode_anomaly import _confusable_name, scan_text

    weak: set[str] = set()
    strong: set[str] = set()
    for tool in tools:
        categories: set[str] = set()
        for category, pattern in IMPERATIVE_PATTERNS:
            match = pattern.search(tool.description)
            if match is None:
                continue
            if category == "exfiltration" and _same_origin(match.group(3), target):
                continue
            categories.add(category)
        categories |= {category for category, _, _ in scan_text(tool.description)}
        categories |= {category for category, _, _ in scan_text(tool.name)}
        if _confusable_name(tool.name) is not None:
            categories.add("confusable_name")
        if categories & STRONG_SIGNAL_CATEGORIES:
            strong.add(tool.name)
        elif categories & WEAK_SIGNAL_CATEGORIES:
            weak.add(tool.name)
    return frozenset(weak - strong)


def build_transport(target: str, image: str, env: dict[str, str]) -> Transport:
    if target.startswith(("http://", "https://")):
        contact = os.environ.get("AP_CONTACT_URL", DEFAULT_CONTACT_URL)
        return StreamableHttpTransport(target, contact_url=contact)
    return StdioTransport(LaunchSpec(image=image, command=shlex.split(target), env=env))


@dataclass(frozen=True)
class EventFrame:
    """One check's completion, for a progress stream. `phase` is the part of
    `check_id` before the first "." (e.g. "revision.cache_scope" -> "revision")
    -- cheap to derive, no new metadata needed on Check itself."""

    check_id: str
    status: str  # "passed" | "errored"
    elapsed_ms: int
    phase: str
    completed: int
    total: int


@dataclass(frozen=True)
class ScanOutcome:
    """Everything a caller (CLI or API) needs to report a completed scan."""

    findings: list[Finding]
    skipped: list[Skipped]
    errored: list[CheckOutcome]
    fingerprint: Fingerprint
    tools: list[ToolRecord]
    edges: list[CapabilityEdge]


def run_scan(
    target: str,
    mode: ScanMode,
    scope: ScopeFile | None,
    *,
    image: str = "python:3.12-slim",
    env: dict[str, str] | None = None,
    checks: Sequence[Check] = ALL_CHECKS,
    today: date | None = None,
    extra_raw: dict[str, dict[str, object]] | None = None,
    invocation_flags: tuple[str, ...] = (),
    on_event: Callable[[EventFrame], None] | None = None,
) -> ScanOutcome:
    """Run the shared scan pipeline: refuse-if-unauthorised, connect,
    fingerprint, enumerate tools, decide which checks apply, run them.

    `extra_raw` and `invocation_flags` are how cli.py layers its CLI-only
    extras (--config/--env-file/--repo/--agent-transcript, and the
    reproduction-command flags) onto the shared ScanContext without this
    function knowing what a Path option is; the API never passes either.
    `extra_raw` entries win over what this function derives itself (an
    operator-supplied --env-file must override the stdio launch env fallback,
    exactly like the pre-extraction cli.py did with its own if/else).
    """
    today = today if today is not None else date.today()
    env = env if env is not None else {}

    # The one call site for the top-level "active mode needs authorisation"
    # gate -- CLI and API both route through this, so they cannot drift
    # (hard constraint 1). require_scope(None, ...) already raises with the
    # right message and missing_field="scope_file" for "no scope at all".
    if mode is ScanMode.ACTIVE:
        require_scope(scope, check_id="scan", target=target, today=today)

    transport = build_transport(target, image, env)
    try:
        result: Fingerprint = fingerprint(transport)

        # Lazy imports, deliberately: tests monkeypatch these at their
        # original definition module (agent_perimeter.checks.revision.
        # oauth_metadata / agent_perimeter.checks.static.auth_probe), which
        # only takes effect on a name looked up at call time, not one bound
        # at this module's import time.
        from agent_perimeter.checks.revision.oauth_metadata import fetch_oauth_metadata
        from agent_perimeter.checks.static.auth_probe import probe_auth_challenge

        raw: dict[str, dict[str, object]] = {}
        for method in ("server/discover", "tools/list"):
            try:
                raw[method] = transport.request(method)
            except TransportError:
                continue
        metadata = fetch_oauth_metadata(target)
        if metadata is not None:
            raw["oauth/metadata"] = metadata
        # A plain unauthenticated request any client would make, not a
        # crafted payload -- no scope file needed. static.auth_mode and
        # revision.cache_scope both read this to distinguish "no auth
        # evidence" from "the probe didn't run".
        auth_probe = probe_auth_challenge(target)
        if auth_probe:
            raw["_auth_probe"] = auth_probe

        # `Transport` is a plain request()/close() protocol; only a stdio
        # target's launch environment carries `launch_spec`. Probed with
        # getattr rather than isinstance so any transport that exposes the
        # attribute is picked up. `extra_raw` (an operator-supplied
        # --env-file) overrides this below, exactly like the pre-extraction
        # if/else did.
        launch_spec = getattr(transport, "launch_spec", None)
        if launch_spec is not None and launch_spec.env:
            raw["_env"] = dict(launch_spec.env)

        if extra_raw:
            raw.update(extra_raw)

        tools = enumerate_tools(transport)
        ambiguous = compute_ambiguous_tools(tools, target)

        context = ScanContext(
            target=target,
            transport=transport,
            fingerprint=result,
            tools=tools,
            raw=raw,
            scope=scope,
            ambiguous_tools=ambiguous,
            invocation_flags=invocation_flags,
        )

        # No real model provider is wired anywhere in this plan yet
        # (bok-core's gateway doesn't exist) -- False is the honest current
        # state, not a config knob: without it llm_judge would run for real
        # and emit a fabricated Method.MODEL finding.
        runnable, skipped = applicable(
            list(checks),
            result.features,
            scope=scope,
            target=target,
            today=today,
            models_available=False,
        )

        on_check = None
        if on_event is not None:
            total = len(runnable) + len(skipped)
            completed = 0
            event_cb = on_event  # narrowed to non-None here; closed over below

            def _on_check(check: Check, status: str, elapsed_ms: float) -> None:
                nonlocal completed
                completed += 1
                event_cb(
                    EventFrame(
                        check_id=check.id,
                        status=status,
                        elapsed_ms=round(elapsed_ms),
                        phase=check.id.split(".", 1)[0],
                        completed=completed,
                        total=total,
                    )
                )

            on_check = _on_check

        findings, errored = run_checks(runnable, context, on_check=on_check)
    finally:
        transport.close()

    edges = build_graph(tools)
    return ScanOutcome(
        findings=findings,
        skipped=skipped,
        errored=errored,
        fingerprint=result,
        tools=tools,
        edges=edges,
    )
