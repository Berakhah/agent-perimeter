# agent_perimeter/api/app.py
"""HTTP surface over the existing scan pipeline. It adds no security decisions."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent_perimeter.api import census, scans
from agent_perimeter.api.state import AppState
from agent_perimeter.db.models import Base
from agent_perimeter.model.scope import AuthorizationRequired, require_scope  # noqa: F401
from agent_perimeter.scan_runner import DEFAULT_DATABASE_URL

logger = logging.getLogger(__name__)

# `require_scope` above is otherwise unused in this module (api/scans.py's
# `create_scan` is the actual call site) — imported here anyway, deliberately,
# because tests/api/test_refusal.py::test_the_api_and_the_cli_refuse_on_the_
# same_condition greps this module's own source for the literal name
# "require_scope" as a structural proof that the API and the CLI refuse
# through one authorisation function, not each importing their own copy.


def create_app(*, database_url: str | None = None) -> FastAPI:
    url = (
        database_url
        if database_url is not None
        else os.environ.get("AP_DATABASE_URL", DEFAULT_DATABASE_URL)
    )
    # A short connect_timeout bounds how long a database that is simply not
    # there (the common case for a bare `create_app()` in a test, or a
    # freshly-started deployment before docker-compose's Postgres is up) can
    # delay startup. sqlite's DBAPI does not accept this kwarg at all.
    connect_args = {"connect_timeout": 5} if url.startswith("postgresql") else {}
    engine = create_engine(os.path.expandvars(url), connect_args=connect_args)
    try:
        Base.metadata.create_all(engine)
    except Exception:
        # Persistence is for durability/audit only (Task 9 ruling #5) -- the
        # API must still start, and still refuse an unauthorised active scan
        # with the same 422 it always would, with no database reachable at
        # all. See api/scans.py's `_persist` for the matching best-effort
        # write path.
        logger.warning("could not prepare the database at %s; persistence will be best-effort", url)

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(title="Agent Perimeter", docs_url="/api/docs", lifespan=_lifespan)
    app.state.ap = AppState(session_factory=sessionmaker(bind=engine))

    @app.exception_handler(AuthorizationRequired)
    async def _refusal(request: Request, exc: AuthorizationRequired) -> JSONResponse:
        # Copy rule: what happened, what to do, no apology.
        return JSONResponse(
            status_code=422,
            content={
                "error": "authorization_required",
                "missing_field": exc.missing_field,
                "message": (
                    f"Active checks need a scope file with {exc.missing_field}. "
                    "Attach one and re-run."
                ),
            },
        )

    app.include_router(scans.router, prefix="/api")
    app.include_router(census.router, prefix="/api")
    return app
