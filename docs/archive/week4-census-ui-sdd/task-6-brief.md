### Task 6: Census run pipeline, CLI command, and the passive-only guarantee

**Files:**
- Create: `agent_perimeter/census/run.py`
- Modify: `agent_perimeter/cli.py`
- Test: `tests/census/test_run.py`
- Test: `tests/census/test_passive_only.py`

**Interfaces:**
- Produces: `method_hash() -> str`; `run_census(session, client, *, endpoint, tier2_n) -> CensusRun`; CLI `agent-perimeter census`.
- Consumes: `paginate`, `fetch_artifact`, `detect_features`, `top_n`, `CensusRun`, `CensusRecord`.

**This task's most important artifact is a test, not a feature.** "Public-registry scanning is passive only" is a hard constraint from `CLAUDE.md`; a comment saying so is worth nothing. `test_passive_only.py` walks the import graph of `agent_perimeter.census` with `ast` and fails if any transport or active-check module is reachable from it. The guarantee then survives a future contributor who has not read this plan.

- [ ] **Step 1: RED — the structural guarantee**

Create `tests/census/test_passive_only.py`:

```python
import ast
import re
from pathlib import Path

FORBIDDEN_PREFIXES = (
    "agent_perimeter.transport",
    "agent_perimeter.checks.active",
    "agent_perimeter.checks.injection",
    "agent_perimeter.discover",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_census_can_never_reach_a_transport_or_an_active_check() -> None:
    """The census must be structurally incapable of touching a third-party server."""
    offences: list[str] = []
    for path in Path("agent_perimeter/census").rglob("*.py"):
        for name in _imports(path):
            if name.startswith(FORBIDDEN_PREFIXES):
                offences.append(f"{path}: {name}")
    assert offences == [], f"census reached a live-traffic module: {offences}"


TIER3 = Path("agent_perimeter/census/tier3.py")
_METHOD_RE = re.compile(r"^[a-z]+/[a-zA-Z]+$")


def test_every_module_but_tier3_talks_only_to_the_allowed_hosts() -> None:
    """Tiers 1-2 are artifact-only: the host list is closed and literal."""
    allowed = {
        "registry.modelcontextprotocol.io",
        "pypi.org",
        "registry.npmjs.org",
        "pypistats.org",
        "api.npmjs.org",
    }
    src = "\n".join(
        p.read_text(encoding="utf-8")
        for p in Path("agent_perimeter/census").rglob("*.py")
        if p != TIER3
    )
    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts <= allowed, f"unexpected host in census: {hosts - allowed}"


def test_tier3_sends_exactly_one_method_and_owns_no_host() -> None:
    """Tier 3's targets come from the frame, so it is constrained by shape, not by host.

    This is the guarantee that makes a live `server/discover` passive discovery
    rather than an active probe. It must be impossible to widen by accident.
    """
    src = TIER3.read_text(encoding="utf-8")

    methods = {
        node.value
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _METHOD_RE.fullmatch(node.value)
    }
    assert methods == {"server/discover"}, f"tier3 may send only server/discover, found {methods}"

    hosts = set(re.findall(r"https://([a-z0-9.\-]+)/", src))
    assert hosts == set(), f"tier3 must take every target from the frame, found {hosts}"
```

The second test is why Tier 3 is confined to one module. `methods == {"server/discover"}`
is an **equality, not a subset**: adding `initialize` or `tools/list` fails it, and so does
deleting the constant the request is built from — a guard that silently passes once the
thing it guards is removed is worse than no guard. Step 3 breaks both directions.

It walks the **AST**, not the raw source, so a docstring explaining which methods Tier 3
deliberately does *not* send cannot false-fire it; a substring regex over the source does.
Both directions were exercised against synthetic modules before this plan shipped.

The strictness is deliberate and worth stating, because a future contributor will hit it:
*any* `word/word` string constant in `tier3.py` fails this test, not just a JSON-RPC method.
The module is thirty lines whose entire job is one request. There is no legitimate second
path-shaped constant, and permitting one is how the boundary erodes.

Run: `uv run pytest tests/census/test_passive_only.py`
Expected: passes trivially now (no `run.py` yet) — **which is why Step 3 deliberately tries to break it.**

- [ ] **Step 2: GREEN — the pipeline**

Create `agent_perimeter/census/run.py`:

```python
"""Census orchestration. Registry, then artifacts. No live server, ever."""

from __future__ import annotations

import hashlib
import inspect
from datetime import UTC, datetime

from agent_perimeter.census import artifacts, detect, fetch, sample


def method_hash() -> str:
    """Hash of the collection code itself, so a published number names its method.

    B9 requires versioned results. Hashing the four modules that decide what gets
    collected means a changed method cannot silently reuse an old report's label.
    """
    h = hashlib.sha256()
    for module in (fetch, artifacts, detect, sample):
        h.update(inspect.getsource(module).encode())
    return h.hexdigest()[:16]


def run_census(session, client, *, endpoint: str, tier2_n: int) -> CensusRun:
    started = datetime.now(UTC)
    log = fetch.FetchLog()
    run = CensusRun(
        started_at=started,
        population_size=0,
        tool_version=__version__,
        method_hash=method_hash(),
        tier2_n=tier2_n,
        registry_endpoint=endpoint,
    )
    session.add(run)
    session.flush()

    entries = list(fetch.paginate(client, endpoint, log))
    run.population_size = len(entries)

    ranked = sample.rank(client, entries)
    tier2 = {r.entry.registry_id for r in sample.top_n(ranked, tier2_n)}

    for entry in entries:
        record = _record_for(run, entry, ranked)
        if entry.registry_id in tier2 and entry.coords is not None:
            result = artifacts.fetch_artifact(client, entry.coords)
            record.fetch_status = result.status.value
            record.fetch_detail = result.detail
            if result.root is not None:
                fp = detect.detect_features(result.root)
                record.sdk_version = fp.sdk_version
                record.feature_set_json = {
                    "features": sorted(f.value for f in fp.features),
                    "derivation": fp.claim.derivation.value,
                    "confidence": fp.claim.confidence,
                    "caveat": fp.claim.caveat,
                    "is_unknown": fp.is_unknown,
                }
        session.add(record)

    run.fetch_failures = log.failures + _record_failures(session, run)
    run.finished_at = datetime.now(UTC)
    session.commit()
    return run
```

- [ ] **Step 3: Prove the guard bites**

Temporarily add `from agent_perimeter.transport import streamable_http` to `run.py`, then:

Run: `uv run pytest tests/census/test_passive_only.py`
Expected: **fails** with `census reached a live-traffic module: agent_perimeter/census/run.py: agent_perimeter.transport.streamable_http`.

Remove the import. Re-run: passes. A guard that has never been seen to fail is not known to work.

- [ ] **Step 4: The CLI command**

Add to `agent_perimeter/cli.py`:

```python
@app.command()
def census(
    endpoint: Annotated[str, typer.Option(help="Registry API base URL.")] = DEFAULT_REGISTRY,
    tier2_n: Annotated[int, typer.Option(help="Tier-2 packages per ecosystem.")] = 200,
    out: Annotated[Path, typer.Option(help="Directory for the report and raw data.")] = Path(
        "docs/census"
    ),
) -> None:
    """Collect a passive census of the public MCP registry.

    Reads the registry API and published package artifacts. Never connects to a
    third-party MCP server.
    """
```

- [ ] **Step 5: Run it small, end to end**

```bash
uv run agent-perimeter census --tier2-n 5 --out /tmp/census-smoke
```

Expected: completes; prints population size, tier-2 `n`, fetch failures, and the method hash. Confirm `fetch_failures` is printed even when zero — a number that only appears when it is bad is a number nobody trusts.

- [ ] **Step 6: Commit**

```bash
uv run pytest tests/census/ && uv run mypy --strict agent_perimeter
git add agent_perimeter/census/run.py agent_perimeter/cli.py tests/census/
git commit -m "feat: census pipeline with a structural passive-only guarantee"
```

---

