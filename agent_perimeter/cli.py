"""agent-perimeter — command line entry point.

Week 1 scope: connect, fingerprint, report the revision claimed and the
features observed, and refuse active mode without authorisation.
"""

from __future__ import annotations

import os
import shlex
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_perimeter.checks.registry import applicable, summarise_skips
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope
from agent_perimeter.transport.base import Transport
from agent_perimeter.transport.revision import Fingerprint, fingerprint
from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

DEFAULT_CONTACT_URL = "https://github.com/USER/agent-perimeter"


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
    try:
        result: Fingerprint = fingerprint(transport)
    finally:
        transport.close()

    claimed = result.revision_claimed.value if result.revision_claimed else "unknown"
    observed = ", ".join(sorted(feature.value for feature in result.features)) or "none"
    typer.echo(f"Revision claimed:  {claimed}")
    typer.echo(f"Features observed: {observed}")

    runnable, skipped = applicable(
        [], result.features, scope=scope, target=target, today=date.today()
    )
    typer.echo(f"Checks run:        {len(runnable)}")
    typer.echo("No findings for the checks that ran. " + summarise_skips(skipped))
