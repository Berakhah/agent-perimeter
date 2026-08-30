"""agent-perimeter — command line entry point.

Week 1 scope: connect, fingerprint, report the revision claimed and the
features observed, and refuse active mode without authorisation.
"""

from __future__ import annotations

import json
import os
import shlex
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.registry import applicable, summarise_skips
from agent_perimeter.discover.enumerate import ToolRecord
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope
from agent_perimeter.transport.base import Transport, TransportError
from agent_perimeter.transport.revision import Fingerprint, fingerprint
from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

DEFAULT_CONTACT_URL = "https://github.com/USER/agent-perimeter"

# The plain `Severity` StrEnum sorts alphabetically (critical, high, info, low,
# medium) — wrong order. This is the actual severity ranking (revision §2.7).
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Ambiguity, concretely (revision §2.5): a tool whose description matched only
# a *weak* deterministic signal and no *strong* one is handed to the model
# judge for escalation; a strong signal alone is confident enough on its own.
WEAK_SIGNAL_CATEGORIES = frozenset({"model_directive", "exfiltration", "confusable_name"})
STRONG_SIGNAL_CATEGORIES = frozenset(
    {"override", "concealment", "role_claim", "bidi_override", "zero_width", "tag_character"}
)


def compute_ambiguous_tools(tools: list[ToolRecord]) -> frozenset[str]:
    from agent_perimeter.checks.descriptions.imperative_injection import IMPERATIVE_PATTERNS
    from agent_perimeter.checks.descriptions.unicode_anomaly import _confusable_name, scan_text

    weak: set[str] = set()
    strong: set[str] = set()
    for tool in tools:
        categories = {
            category
            for category, pattern in IMPERATIVE_PATTERNS
            if pattern.search(tool.description)
        }
        categories |= {category for category, _, _ in scan_text(tool.description)}
        if _confusable_name(tool.name) is not None:
            categories.add("confusable_name")
        if categories & STRONG_SIGNAL_CATEGORIES:
            strong.add(tool.name)
        elif categories & WEAK_SIGNAL_CATEGORIES:
            weak.add(tool.name)
    return frozenset(weak - strong)


class ScanMode(StrEnum):
    """A free-form `str` let `--mode actve` (typo) silently run a passive
    scan with no warning. An enum makes Typer reject an invalid value
    outright instead of misinterpreting it as "not active"."""

    PASSIVE = "passive"
    ACTIVE = "active"


def _parse_env(pairs: list[str]) -> dict[str, str]:
    """Parse repeated `--env KEY=VALUE` options.

    Fails closed: a value with no `=` is rejected rather than silently
    dropped or guessed at.
    """
    env: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            typer.echo(f"--env value {pair!r} is not in KEY=VALUE form.")
            raise typer.Exit(code=2)
        key, _, value = pair.partition("=")
        env[key] = value
    return env


def _build_transport(target: str, image: str, env: dict[str, str]) -> Transport:
    if target.startswith(("http://", "https://")):
        contact = os.environ.get("AP_CONTACT_URL", DEFAULT_CONTACT_URL)
        return StreamableHttpTransport(target, contact_url=contact)
    return StdioTransport(LaunchSpec(image=image, command=shlex.split(target), env=env))


app = typer.Typer(
    add_completion=False,
    help="MCP security posture scanner.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """MCP security posture scanner."""
    pass


@app.command()
def scan(
    target: Annotated[str, typer.Option(help="A URL, or a stdio command to launch.")],
    mode: Annotated[ScanMode, typer.Option(help="passive or active")] = ScanMode.PASSIVE,
    scope_file: Annotated[Path | None, typer.Option(help="Authorisation for active mode.")] = None,
    image: Annotated[
        str, typer.Option(help="Container image for stdio targets.")
    ] = "python:3.12-slim",
    env: Annotated[
        list[str],
        typer.Option(help="Environment variable KEY=VALUE for a stdio target, may be repeated."),
    ] = [],  # noqa: B006 -- read-only; typer needs a concrete default, never mutated
    only: Annotated[str | None, typer.Option(help="Run a single check by id.")] = None,
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF 2.1.0 here.")] = None,
    repo: Annotated[Path | None, typer.Option(help="Local repo for history scanning.")] = None,
    config: Annotated[
        Path | None, typer.Option(help="MCP client config to scan for secrets.")
    ] = None,
    env_file: Annotated[
        Path | None, typer.Option("--env-file", help="Env file to scan for secrets.")
    ] = None,
) -> None:
    try:
        scope = ScopeFile.model_validate_json(scope_file.read_text()) if scope_file else None
    except (OSError, ValidationError) as exc:
        typer.echo(f"Could not read scope file: {exc}")
        raise typer.Exit(code=2) from None
    env_dict = _parse_env(env)

    if mode == ScanMode.ACTIVE:
        if scope is None:
            typer.echo(
                "Active mode requires a scope file naming target, authorising_party, "
                "authorised_on and attestation. Pass --scope-file."
            )
            raise typer.Exit(code=2)
        try:
            require_scope(scope, check_id="scan", target=target, today=date.today())
        except AuthorizationRequired as exc:
            typer.echo(str(exc))
            raise typer.Exit(code=2) from None

    try:
        transport = _build_transport(target, image, env_dict)
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}")
        raise typer.Exit(code=2) from None

    # The transport stays open for the whole scan, not just the fingerprint
    # call: checks run against `context.transport` too (revision.
    # header_body_mismatch probes it directly), and enumerate_tools() below
    # needs a live connection. One container/connection per scan, closed once
    # at the end — see transport/stdio.py's module docstring.
    try:
        result: Fingerprint = fingerprint(transport)

        claimed = result.revision_claimed.value if result.revision_claimed else "unknown"
        observed = ", ".join(sorted(feature.value for feature in result.features)) or "none"
        typer.echo(f"Revision claimed:  {claimed}")
        typer.echo(f"Features observed: {observed}")

        from agent_perimeter.checks.all_checks import ALL_CHECKS, run_checks, summarise_errors
        from agent_perimeter.checks.context import ScanContext
        from agent_perimeter.checks.revision.oauth_metadata import fetch_oauth_metadata
        from agent_perimeter.checks.static.auth_probe import probe_auth_challenge
        from agent_perimeter.discover.enumerate import enumerate_tools
        from agent_perimeter.report.sarif import to_sarif

        raw: dict[str, dict[str, object]] = {}
        for method in ("server/discover", "tools/list"):
            try:
                raw[method] = transport.request(method)
            except TransportError:
                continue
        metadata = fetch_oauth_metadata(target)
        if metadata is not None:
            raw["oauth/metadata"] = metadata
        # Same category as the OAuth metadata fetch: a plain unauthenticated
        # request any client would make, not a crafted payload — no scope
        # file needed. static.auth_mode and revision.cache_scope both read
        # this to distinguish "no auth evidence" from "the probe didn't run".
        auth_probe = probe_auth_challenge(target)
        if auth_probe:
            raw["_auth_probe"] = auth_probe
        if repo is not None:
            raw["_repo_path"] = {"path": str(repo)}

        # Revision 2.5: _config / _env are read by secrets/* but nothing wrote
        # them until now. --config and --env-file are the operator-supplied
        # paths; a stdio target additionally contributes its own launch
        # environment.
        if config is not None:
            raw["_config"] = json.loads(config.read_text(encoding="utf-8"))
            raw["_config_path"] = {"path": str(config)}
        if env_file is not None:
            parsed_env: dict[str, object] = {}
            for line in env_file.read_text().splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    parsed_env[key] = value
            raw["_env"] = parsed_env
            raw["_env_path"] = {"path": str(env_file)}
        else:
            # `Transport` is a plain request()/close() protocol; only a
            # stdio target's launch environment carries `launch_spec`. This
            # probes for it with getattr rather than isinstance so any
            # transport that exposes the attribute is picked up, not just
            # StdioTransport by name.
            launch_spec = getattr(transport, "launch_spec", None)
            if launch_spec is not None and launch_spec.env:
                raw["_env"] = dict(launch_spec.env)

        tools = enumerate_tools(transport)
        ambiguous = compute_ambiguous_tools(tools)

        context = ScanContext(
            target=target,
            transport=transport,
            fingerprint=result,
            tools=tools,
            raw=raw,
            scope=scope,
            ambiguous_tools=ambiguous,
        )

        selected = [c for c in ALL_CHECKS if only is None or c.id == only]
        runnable, skipped = applicable(
            selected, result.features, scope=scope, target=target, today=date.today()
        )

        findings, errored = run_checks(runnable, context)
    finally:
        transport.close()

    for finding in sorted(findings, key=lambda f: SEVERITY_RANK[f.severity]):
        typer.echo(f"[{finding.severity.value}] {finding.check_id}: {finding.title}")

    summary = " ".join(
        part for part in (summarise_skips(skipped), summarise_errors(errored)) if part
    )
    if not findings:
        typer.echo("No findings for the checks that ran. " + summary)
    else:
        typer.echo(f"{len(findings)} findings. " + summary)

    if sarif is not None:
        workspace = sarif.parent if sarif.parent != Path("") else Path(".")
        sarif.write_text(
            json.dumps(
                to_sarif(
                    findings,
                    target=target,
                    tool_version="0.1.0",
                    fingerprint=result,
                    workspace=workspace,
                ),
                indent=2,
            )
        )
        typer.echo(f"SARIF written to {sarif}")
