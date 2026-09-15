#!/usr/bin/env bash
# Asserts the compose stack is actually up, not just "docker compose" exiting
# 0. Run after `docker compose up -d --wait`. Fails closed: any assertion
# failing exits non-zero with a message naming what broke, no narration.
set -euo pipefail

fail() { echo "FAIL: $1" >&2; exit 1; }

curl -fsS localhost:8000/api/health >/dev/null || fail "api not healthy"
curl -fsS localhost:3000/ >/dev/null || fail "web not serving"

# A second, verified deviation from the brief's own shown script here (task
# 17): the brief posts a stdio-shaped target ("python /server.py"), but
# agent_perimeter/api/scans.py::create_scan classifies the target's transport
# *before* checking for a scope file (Task 9 ruling #3 -- this API only ever
# accepts http(s) targets; a stdio target gets a 400 "unsupported_target"
# naming the CLI instead, proven by
# tests/api/test_scans.py::test_a_stdio_target_is_refused_with_a_400_naming_the_cli).
# Posting a stdio-shaped target here would always get 400, never 422,
# regardless of whether the scope-file refusal itself is working -- an http(s)
# target is what actually exercises the assertion this check exists for.
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.invalid/mcp","mode":"active"}')
[ "$code" = "422" ] || fail "active scan without a scope file returned $code, expected 422"

# Assert "at head" by alembic's own marker rather than a hardcoded revision
# number. The brief's shown script said `grep -q 0004`, task 17 corrected it
# to `0003`, and the census work then moved the head to 0005 -- the first
# genuine clean-machine run (docs/evidence/clean-machine.md) failed on
# exactly that third drift. `alembic current` prints `<rev> (head)` only when
# the database is at the latest revision, so this stays correct as
# migrations are added. Run directly via `alembic`, not `uv run alembic`: the
# api image installs this project with `pip install .` (Dockerfile), not as
# a uv-managed venv, so `alembic` is already on PATH and `uv` itself is never
# installed in the image.
docker compose exec -T api alembic current | grep -q '(head)' || fail "migrations not at head"

echo "OK: api, web, refusal path and migrations all verified"
