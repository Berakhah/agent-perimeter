# Compose verification record

**This is not a clean-machine run.** A genuine clean-machine verification —
`git clone` on a fresh VM or a container with only Docker installed, nothing
else — is still outstanding and is explicitly out of scope for the task that
produced this record (see the scope boundary recorded in this plan's task-17
brief/progress notes). What follows is a best-effort verification of the same
`docker compose up -d --wait && ./scripts/smoke.sh` sequence run **inside the
existing development sandbox** — the same machine and checkout every other
task in this plan was implemented on, with Docker Desktop already installed,
`uv`/`npm`/Python package registries already warm, and this repository's own
`.venv`/`node_modules` present alongside (but not used by) the containers.
Treat the numbers below as "the compose topology and healthchecks are
internally correct" evidence, not as "a stranger with a bare VM will see
this" evidence. That second claim needs an actual fresh VM run before it can
be made honestly.

## Environment

- **Date:** 2026-09-07
- **Host OS:** Windows 11 Home 10.0.26200 (Docker Desktop, WSL2 backend)
- **Docker:** `Docker version 29.7.2, build a7dcaa6`
- **Docker Compose:** `Docker Compose version v5.4.0`
- **Repo state:** this task's own worktree/branch (`week4-census-ui`), working
  tree clean before the run, `cp .env.example .env` performed exactly as the
  README's quickstart instructs (no manual edits to the copied `.env`).

## What was run

```bash
cp .env.example .env
docker compose up -d --build --wait
./scripts/smoke.sh
```

## Outcome: green

```
 Container week4-census-ui-db-1 Healthy
 Container week4-census-ui-api-1 Healthy
 Container week4-census-ui-web-1 Healthy
```

```
$ docker compose exec -T api alembic current
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
0003 (head)
```

```
$ ./scripts/smoke.sh
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
OK: api, web, refusal path and migrations all verified
```

All three always-on services (`db`, `api`, `web`) reached `healthy` and the
smoke script's four assertions (API liveness, web serving, the 422
scope-file refusal on an active scan, migrations at head) all passed.

The fourth compose service, `fixture` (the Week 1 parameterised MCP stdio
fixture, gated behind `--profile demo` since it is a stdio server, not a
daemon — see docker-compose.yml's comment on that service), was also built
and exercised directly in this same sandbox run:

```
$ docker compose --profile demo build fixture   # built clean
$ echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | docker compose --profile demo run --rm -T fixture
{"jsonrpc": "2.0", "id": 1, "result": {"tools": [...]}}
```

## Timing (caveated — not a from-clean-clone number)

A `docker compose up -d --build --wait` timed after removing this session's
own previously-built `api`/`web` images (`docker compose down --rmi local`)
completed in **38 seconds**, with the smoke script adding **2 more seconds**
(40s total from `up` to a fully green smoke run). This number is not
representative of a true cold clone-to-green time: Docker's *layer* cache
(base images, and — critically — the `npm ci`/`pip install` layers
themselves, which are content-addressed and were not evicted by removing the
final image) was still warm from the same session's earlier build a few
minutes prior, and the host's package registries were already reachable and
recently used. The very first build in this session, with nothing at all
cached, took roughly 82s for the `api` image (dominated by `pip install .`
resolving and downloading ~35 wheels, ~74s of that alone) and roughly 133s
for the `web` image (dominated by `npm ci`, ~60s, and `next build`, ~38s) —
call it on the order of **3–4 minutes** wall-clock for a genuinely first-ever
build on this sandbox, run as two separate sequential `docker compose build`
invocations rather than the parallelised `docker compose up --build`. A real
clean-machine run should be expected to land somewhere in that neighbourhood
or a bit higher (slower disk, no local registry mirror, first-time Docker
Desktop startup overhead) — this record does not attempt to be more precise
than that about a machine nobody has actually run this on yet.

## What this run did and did not need beyond the README

Nothing needed a step the README doesn't already state. `cp .env.example
.env` followed by `docker compose up -d --wait` and `./scripts/smoke.sh`
worked with no manual intervention, no undocumented environment variable, and
no manual `docker` command outside the three shown above. (Per the brief's
own instruction for this step: "if anything needed a step not in the README,
add the step to the README rather than to the transcript" — nothing did, so
nothing was added.)

## Two real, verified bugs this run caught and fixed

Both are documented inline where they were fixed (`scripts/smoke.sh`,
`docker-compose.yml`, `Dockerfile`, `alembic.ini`), noted here because they
are exactly the class of thing a compose verification step exists to catch:

1. **Migration number.** The brief's own shown `smoke.sh` checked for
   migration `0004`; the real migration head in this repository is `0003`
   (`migrations/versions/0003_census.py`). Fixed in `scripts/smoke.sh`.
2. **The refusal-path smoke assertion posted a stdio-shaped target
   (`"python /server.py"`) to prove the scope-file refusal, but
   `agent_perimeter/api/scans.py` classifies a target's transport *before*
   checking for a scope file — a stdio target always gets `400
   unsupported_target`, never `422`, regardless of whether the scope-file
   refusal itself works.** This was caught by actually running the script
   against the real API in this sandbox (it failed with `FAIL: active scan
   without a scope file returned 400, expected 422`), not by static reading.
   Fixed by posting an `https://` target instead, which is what the
   assertion needs to actually exercise the 422 path (confirmed against
   `tests/api/test_scans.py::test_a_stdio_target_is_refused_with_a_400_naming_the_cli`,
   which independently documents the same classify-before-scope ordering).

Neither bug would have been caught by re-reading the brief's script; both
were only visible by actually executing it against a live stack, which is
the entire point of doing even a best-effort sandbox run rather than skipping
Step 3 outright.

## Outstanding

A genuine clean-machine (fresh VM / container with only Docker installed) run
is still outstanding. Per the scope boundary for this task, it is explicitly
not attempted here and is left for the human partner to run before Step 8's
publish actions (also explicitly out of scope for this task) are taken.
