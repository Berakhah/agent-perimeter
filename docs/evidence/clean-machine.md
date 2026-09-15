# Clean-machine verification record

**This is a genuine clean-machine run.** A fresh GitHub-hosted VM
(`ubuntu-latest`) with nothing of this project on it — no checkout, no
build cache, no `.venv`, no `node_modules` — did a literal `git clone` of
the public repository and ran the README's Quickstart verbatim. It is
reproducible by anyone with access to the repository: **Actions →
clean-machine → Run workflow**, or `gh workflow run clean-machine.yml`.
The workflow that ran it is `.github/workflows/clean-machine.yml`; it
deliberately uses no `actions/checkout` and no cache actions, so the runner
sees exactly what a stranger following the README sees.

## The run

- **Run:** <https://github.com/Berakhah/agent-perimeter/actions/runs/34942171856>
  (workflow `clean-machine`, job `quickstart`, conclusion **success**)
- **Commit verified:** `08e85f3` on branch `clean-machine-verification`
  (pinned by `git checkout $GITHUB_SHA` after the clone, so the record
  names one exact tree)
- **Date:** 2026-09-15, 07:31:53Z → 07:33:15Z (**82 s** job wall-clock,
  including runner setup and teardown)
- **Runner:** Ubuntu 24.04.5 LTS, Linux 6.17.0-1022-azure x86_64
- **Docker:** Client 28.0.4 / Server 28.0.4
- **Docker Compose:** v2.38.2

Note both Docker versions differ from the development sandbox's
(29.8.0 / Compose v5.4.0, below) — the stack comes up green on both.

### State of the VM before anything was cloned

```
REPOSITORY                                   TAG       SIZE
ghcr.io/github/gh-aw-firewall/agent          latest    569MB
ghcr.io/github/gh-aw-firewall/api-proxy      latest    231MB
ghcr.io/github/gh-aw-mcpg                    latest    181MB
ghcr.io/dependabot/dependabot-updater-core   latest    826MB
ghcr.io/github/github-mcp-server             latest    46.8MB
ghcr.io/github/gh-aw-firewall/squid          latest    43.1MB

TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          6         0         1.88GB    1.88GB (100%)
Containers      0         0         0B        0B
Local Volumes   0         0         0B        0B
Build Cache     0         0         0B        0B
```

Six GitHub-owned images are preloaded on every `ubuntu-latest` runner; none
is a base image this project uses (`python:*`, `node:*`, `postgres:*`) and
the **build cache was 0 B**, so the `api` and `web` image builds below were
cold: every base layer pulled, every `pip install` / `npm ci` / `next build`
layer executed from scratch.

## What was run (README "Quickstart", line for line)

```bash
git clone https://github.com/Berakhah/agent-perimeter.git && cd agent-perimeter
cp .env.example .env
docker compose up -d --wait
./scripts/smoke.sh
```

plus the README's opt-in fixture:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | docker compose --profile demo run --rm -T fixture
```

## Outcome: green

```
 api  Built
 web  Built
 Container agent-perimeter-db-1   Healthy
 Container agent-perimeter-api-1  Healthy
 Container agent-perimeter-web-1  Healthy
clone-to-healthy: 62s
```

```
$ ./scripts/smoke.sh
OK: api, web, refusal path and migrations all verified
smoke: 1s
```

```
$ echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
    | docker compose --profile demo run --rm -T fixture
{"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "read_file", ...}], "resultType": "complete", ...}}
```

All three always-on services reached `healthy`, the smoke script's four
assertions (API liveness, web serving, `422` scope-file refusal on an active
scan, migrations at head) passed, and the stdio fixture answered
`tools/list`.

## Timing

| Stage | Wall-clock |
|---|---|
| `docker compose up -d --wait` — cold build of `api` (243 MB) and `web` (773 MB), pull `postgres:16-alpine`, migrate, three healthchecks | **62 s** |
| `./scripts/smoke.sh` | **1 s** |
| Whole job incl. runner setup, clone, fixture build+run, teardown | **82 s** |

This is faster than the 3–4 minutes the earlier sandbox record estimated for
a cold build: GitHub-hosted runners sit next to a registry mirror with very
high download bandwidth, and the sandbox estimate was dominated by wheel and
npm downloads. A laptop on ordinary broadband should expect the higher end.

## What this run needed beyond the README

Nothing. Each README step ran unmodified with no undocumented environment
variable and no manual `docker` command. The first attempt at this run
(<https://github.com/Berakhah/agent-perimeter/actions/runs/34941948403>)
did fail — see below — and the fix went into `scripts/smoke.sh`, not into
the README or a transcript.

## Bug this run caught and fixed

**Third occurrence of the pinned-migration-number drift.** The stack came up
healthy on the first fresh-VM attempt, but `smoke.sh` failed with `FAIL:
migrations not at head`: it still grepped `alembic current` for `0003`,
while the census work had since added `0004_census_run_salt.py` and
`0005_census_sample_seed.py`. The brief's own script had said `0004`; task
17 corrected it to `0003`; the head then moved again. `scripts/smoke.sh` now
asserts on alembic's own `(head)` marker, which stays correct as migrations
are added. Nothing on the development sandbox would have caught this — its
Postgres volume was already migrated and the smoke script had not been
re-run since the census branch merged.

## Prior record: sandbox run, 2026-09-07 (superseded)

Before this run, the only evidence was a best-effort run of the same
sequence inside the development sandbox (Windows 11, Docker Desktop 29.x /
Compose v5.4.0, warm layer cache, project `.venv` and `node_modules`
present). That run was green too, and caught two real bugs which are still
documented inline where they were fixed: `smoke.sh` checking for migration
`0004` when the head was `0003`, and the refusal-path assertion posting a
stdio-shaped target that `agent_perimeter/api/scans.py` rejects with `400
unsupported_target` before the scope-file check can produce the `422` the
assertion exists to exercise (fixed by posting an `https://` target). The
sandbox record's cold-build estimate of roughly 82 s (`api`) + 133 s
(`web`) sequential is retained above only as the "ordinary broadband"
upper bound; its "not a clean-machine run" caveat no longer applies.
