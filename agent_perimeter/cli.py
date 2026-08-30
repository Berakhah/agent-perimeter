"""agent-perimeter — command line entry point.

Week 1 scope: connect, fingerprint, report the revision claimed and the
features observed, and refuse active mode without authorisation.
"""

from __future__ import annotations

import os
import shlex
from datetime import date
from pathlib import Path
from typing import Annotated

import typer

from agent_perimeter.checks.registry import applicable, summarise_skips
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope
from agent_perimeter.transport.base import Transport
from agent_perimeter.transport.revision import Fingerprint, fingerprint
from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

DEFAULT_CONTACT_URL = "https://github.com/USER/agent-perimeter"


def _build_transport(target: str, image: str) -> Transport:
    if target.startswith(("http://", "https://")):
        contact = os.environ.get("AP_CONTACT_URL", DEFAULT_CONTACT_URL)
        return StreamableHttpTransport(target, contact_url=contact)
    return StdioTransport(LaunchSpec(image=image, command=shlex.split(target)))


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
    mode: Annotated[str, typer.Option(help="passive or active")] = "passive",
    scope_file: Annotated[Path | None, typer.Option(help="Authorisation for active mode.")] = None,
    image: Annotated[
        str, typer.Option(help="Container image for stdio targets.")
    ] = "python:3.12-slim",
) -> None:
    scope = ScopeFile.model_validate_json(scope_file.read_text()) if scope_file else None

    if mode == "active":
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

    transport = _build_transport(target, image)
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
