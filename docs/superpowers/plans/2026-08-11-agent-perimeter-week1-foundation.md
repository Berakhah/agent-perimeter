# Agent Perimeter — Week 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the containment, authorisation and protocol-fingerprinting foundation so that `agent-perimeter scan` can connect to an MCP server over stdio or Streamable HTTP, safely, and report which protocol revision it claims versus which features it actually implements.

**Architecture:** A containerised stdio launcher executes untrusted MCP servers with no network, no host mounts and hard resource caps. A revision fingerprinter calls the mandatory `server/discover` RPC, falls back to `initialize`, then independently observes protocol features — producing a `FeatureSet` that check applicability is predicated on. Checks declare required *features*, never version strings, so partial implementers are handled correctly.

**Tech Stack:** Python 3.12+, `uv`, `ruff`, `mypy --strict`, `pytest`, `hypothesis`, Pydantic v2, Docker (containment), PyYAML, Typer, httpx.

**Spec:** `docs/superpowers/specs/2026-08-11-agent-perimeter-design.md`
**Revision (binding):** `docs/superpowers/specs/2026-08-29-agent-perimeter-plan-revision.md` — **read it first.** It corrects blocking defects in Tasks 4, 8, 9 and 11. Where it and this plan disagree, the revision wins.

> **Blocking corrections to this week, summarised.** Evidence and detail in the revision.
> - **Task 4** — drop the hand-written seccomp profile; omit `--security-opt seccomp=…` so Docker's default applies. The custom allowlist is missing syscalls CPython needs (`unlinkat`, `rt_sigsuspend`, `membarrier`, `socketpair`, …) and is x86_64-only, so it breaks real servers and every ARM host. Keep it as an optional flag with a test proving a real Python MCP server runs under it. Add `--env HOME=/tmp` (no writable home under `--read-only`) and `--ulimit nofile`. Revision §7.2.
> - **Task 4** — **one long-lived container per scan**, not per request. Per-request containers destroy server-minted handle state, break every multi-step probe, and make the Week-3 eval harness uncomputable (~4,000 launches with MCPTox). Revision §7.1.
> - **Task 4** — document the `npx`/`uvx` two-phase launch: materialise the package with network in a build step, then run with `--network none`. Otherwise the most common stdio server form cannot be scanned at all. Revision §7.3.
> - **Task 8** — the fingerprinter must **observe or abstain**. Do not grant `MRTR`, `PARAM_HEADERS`, `SUBSCRIPTIONS_LISTEN` or `STATELESS_META` from the presence of `server/discover`; remove `STATELESS_META` from `Feature`; take the *highest* advertised revision, not the first; give an unparseable revision claim a caveat that does not lie about what the server answered. Revision §2.1–§2.2.
> - **Task 9** — the Streamable HTTP transport as specified **cannot talk to any conforming server**. `_meta` belongs **inside `params`**; the required `MCP-Protocol-Version` header is missing; `Mcp-Name` must come from `params.name`/`params.uri` and only for `tools/call`, `resources/read`, `prompts/get`. Also parse `text/event-stream` responses. Revision §1.3.
> - **Task 11** — **remove the `/var/run/docker.sock` mount.** A container holding the Docker socket is host root, and that container is the one parsing untrusted JSON-RPC. Revision §1.7.

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the spec and `00-SHARED-FOUNDATION.md`.

- **Python 3.12+**, `uv` for dependency management, `ruff` for lint and format, **`mypy --strict`** on every module.
- **Licence: Apache-2.0.** Dependencies must be MIT / Apache-2.0 / BSD / OFL. Flag any AGPL dependency explicitly rather than adopting it.
- **No secrets in the repo, ever — including test fixtures.** `gitleaks` pre-commit hook blocks commits.
- **$0 recurring cost.** No dependency with a paid floor.
- **No model name is ever hardcoded.** Week 1 makes no model calls at all.
- **Coverage floor 75%.** Coverage is a floor, not a goal.
- **TDD is RED-GREEN-REFACTOR, no exceptions.** Write the failing test, watch it fail, implement minimally, watch it pass, commit.
- **Never store a raw secret value** — not in the database, not in logs, not in SARIF output.
- **Every stdio server launches inside a locked-down container**: non-root, read-only rootfs, no network unless the check requires it, tmpfs scratch, seccomp, memory and CPU caps, hard timeout, and **no host mounts**.
- **Copy rule:** errors state what happened and what to do, without apologising. Empty findings read `"No findings for the checks that ran"` plus the count skipped and why — never `"You're secure!"`.
- **Repo is private until first release** (spec §1, `00` §12 Q5). Do not push to a public remote during weeks 1–4.

## Week 1 deliverable

`agent-perimeter scan --target <stdio-command|url>` connects, fingerprints the protocol revision, reports the observed `FeatureSet`, and refuses active checks without a scope file. Sandbox containment is proven by test.

**Definition-of-Done items this plan advances:** DoD 3 (active probes refuse without a scope file — *closed*), DoD 4 (all stdio launches containerised — *closed*), DoD 1 (connection across two spec revisions — *foundation laid, closed in Week 2 once SARIF emits*), DoD 10 (`docker compose up` — *foundation laid*).

---

### Task 1: Repository scaffold and CI

**Files:**
- Create: `pyproject.toml`
- Create: `LICENSE`
- Create: `.gitignore`
- Create: `.pre-commit-config.yaml`
- Create: `.github/workflows/ci.yml`
- Create: `agent_perimeter/__init__.py`
- Create: `tests/__init__.py`
- Modify: `CLAUDE.md:4` (licence line)

**Interfaces:**
- Consumes: nothing.
- Produces: an installable package `agent_perimeter`, version `0.1.0`; a green CI pipeline running `ruff check`, `ruff format --check`, `mypy --strict agent_perimeter`, and `pytest --cov=agent_perimeter --cov-fail-under=75`.

- [ ] **Step 1: Initialise the repository**

```bash
git init
git branch -M main
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "agent-perimeter"
version = "0.1.0"
description = "Security posture scanner for MCP servers and tool-using agents"
requires-python = ">=3.12"
license = { text = "Apache-2.0" }
dependencies = [
    "pydantic>=2.7",
    "pyyaml>=6.0",
    "httpx>=0.27",
    "typer>=0.12",
]

[project.scripts]
agent-perimeter = "agent_perimeter.cli:app"

[dependency-groups]
dev = [
    "pytest>=8.2",
    "pytest-cov>=5.0",
    "hypothesis>=6.100",
    "mypy>=1.10",
    "ruff>=0.5",
    "types-PyYAML>=6.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "S"]
ignore = ["S603", "S607"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]

[tool.mypy]
python_version = "3.12"
strict = true
warn_unreachable = true

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--cov=agent_perimeter --cov-report=term-missing --cov-fail-under=75"
```

Note on the ruff ignores: `S603` and `S607` are `subprocess` warnings. This project launches subprocesses deliberately — that is the product — and the containment built in Task 4 is what makes it safe, not the absence of the call.

- [ ] **Step 3: Add the Apache-2.0 licence and `.gitignore`**

```bash
curl -sL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
printf '%s\n' \
  '__pycache__/' '*.py[cod]' '.venv/' '.pytest_cache/' '.mypy_cache/' \
  '.ruff_cache/' '.coverage' 'htmlcov/' 'dist/' 'build/' '*.egg-info/' \
  '.env' > .gitignore
mkdir -p agent_perimeter tests
touch agent_perimeter/__init__.py tests/__init__.py
```

- [ ] **Step 4: Write `.pre-commit-config.yaml`**

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.7
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

- [ ] **Step 5: Write `.github/workflows/ci.yml`**

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --all-groups
      - run: uv run ruff check .
      - run: uv run ruff format --check .
      - run: uv run mypy --strict agent_perimeter
      - run: uv run pytest
```

- [ ] **Step 6: Fix the resolved licence line in `CLAUDE.md`**

Replace line 4. It currently reads:

```
Weeks 1–4 · Accent: signal amber `oklch(0.72 0.16 68)` · Licence: TBD (Apache-2.0 vs AGPL — open decision)
```

It must read:

```
Weeks 1–4 · Accent: signal amber `oklch(0.72 0.16 68)` · Licence: Apache-2.0
```

- [ ] **Step 7: Create `docs/methodology.md`**

Required in all four repos by `00` §6, and the Week 1 completion gate writes into it. It must exist before anything has findings to record.

```markdown
# Methodology

Every number this project publishes answers these four questions. If a number
appears in the product, the report, or the README and is not answered here, it
is a defect.

## 1. What was counted?
Define every term used, especially "vulnerable" — the word the existing MCP
security literature abuses most.

## 2. Who counted it, and how?
Tool version, collection method, and the exact commands run.

## 3. What was the sample and the population?
Sample size, selection method, collection window, and every fetch failure.
A throttled collection silently invalidates a sample; failures are reported,
not hidden.

## 4. What are the known limitations?
Including the project's own measured false-positive rate, per check class.

---

## Competitive claim verification

Recorded in Week 1. Repository, commit SHA, retrieval date, and what was
searched for.

| Tool | Commit SHA | Retrieved | Revision-aware? | Evidence |
|---|---|---|---|---|
| _pending Week 1_ | | | | |

## Model provider inventory

Per `00` §12 Q3 and spec §9. Not blocking for weeks 1–4 — this project makes
no model calls until the `llm_judge` escalation lands.

| Provider | Reachable | trains_on_data | commercial_use | Limits | structured_output | Live model ids | Terms URL + retrieved |
|---|---|---|---|---|---|---|---|
| _pending_ | | | | | | | |
```

- [ ] **Step 8: Verify the toolchain is green**

Run: `uv sync --all-groups && uv run ruff check . && uv run mypy --strict agent_perimeter`
Expected: no errors. `pytest` is not run yet — there are no tests, and `--cov-fail-under=75` would fail on an empty suite. The first test arrives in Task 2.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: scaffold repository, CI, licence, methodology and tooling"
```

---

### Task 2: `bok-core` contract stand-ins

**Files:**
- Create: `agent_perimeter/_contracts.py`
- Test: `tests/test_contracts.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Method`, `Derivation`, `Severity`, `Sensitivity` (all `StrEnum`); `Claim` (Pydantic model with `value`, `method`, `derivation`, `confidence`, `observed_at`, `parents`, `caveat`, and method `inherited_caveats() -> list[str]`). Every later task constructs `Claim` objects through this module.

**Why this exists:** `bok-core` is not published yet. These are concrete mirrors of the contract in spec §8, not permanent code. When `bok-core` ships, delete this file and change imports to `from bok_core.provenance import Claim`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_contracts.py
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_perimeter._contracts import Claim, Derivation, Method


def test_derived_claim_confidence_cannot_exceed_parents() -> None:
    parent = Claim(
        value=1,
        method=Method.MODEL,
        confidence=0.4,
        observed_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError, match="confidence"):
        Claim(
            value=2,
            method=Method.DERIVED,
            confidence=0.9,
            observed_at=datetime.now(UTC),
            parents=[parent],
        )


def test_caveat_propagates_from_parent() -> None:
    parent = Claim(
        value=1,
        method=Method.DETERMINISTIC,
        observed_at=datetime.now(UTC),
        caveat="sample size 51",
    )
    child = Claim(
        value=2,
        method=Method.DERIVED,
        observed_at=datetime.now(UTC),
        parents=[parent],
    )
    assert child.inherited_caveats() == ["sample size 51"]


def test_deterministic_claim_records_its_derivation() -> None:
    claim = Claim(
        value="net_out",
        method=Method.DETERMINISTIC,
        derivation=Derivation.SCHEMA,
        observed_at=datetime.now(UTC),
    )
    assert claim.derivation is Derivation.SCHEMA
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_contracts.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter._contracts'`

- [ ] **Step 3: Write the minimal implementation**

```python
# agent_perimeter/_contracts.py
"""Local stand-ins for `bok-core` interfaces.

ponytail: `bok-core` is not published yet. These are concrete mirrors of the
contract, not permanent code. When the package ships, delete this module and
import from `bok_core` instead. Requirements raised on `bok-core` are recorded
in docs/superpowers/specs/2026-08-11-agent-perimeter-design.md section 8.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, model_validator


class Method(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL = "model"
    HUMAN = "human"
    DERIVED = "derived"


class Derivation(StrEnum):
    """bok-core requirement 1 — see spec section 8.

    All four are DETERMINISTIC methods with materially different
    trustworthiness, which is why derivation is tracked separately.
    """

    SCHEMA = "schema"
    DESCRIPTION = "description"
    PROBE = "probe"
    ARTIFACT = "artifact"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    SYNTHETIC = "synthetic"
    REDACTED = "redacted"
    CLIENT_CONFIDENTIAL = "client_confidential"


class Claim(BaseModel):
    """A value that carries where it came from and how much to trust it."""

    model_config = ConfigDict(frozen=True)

    value: Any
    method: Method
    derivation: Derivation | None = None
    confidence: float | None = None
    observed_at: datetime
    parents: list[Claim] = []
    caveat: str | None = None

    @model_validator(mode="after")
    def _confidence_never_exceeds_parents(self) -> Self:
        if self.method is not Method.DERIVED or not self.parents:
            return self
        parent_confidences = [p.confidence for p in self.parents if p.confidence is not None]
        if not parent_confidences or self.confidence is None:
            return self
        if self.confidence > min(parent_confidences):
            msg = (
                f"DERIVED confidence {self.confidence} exceeds the minimum parent "
                f"confidence {min(parent_confidences)}"
            )
            raise ValueError(msg)
        return self

    def inherited_caveats(self) -> list[str]:
        """Every caveat in this claim's ancestry, nearest first."""
        found: list[str] = []
        for parent in self.parents:
            if parent.caveat is not None:
                found.append(parent.caveat)
            found.extend(parent.inherited_caveats())
        return found


Claim.model_rebuild()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_contracts.py -v --no-cov`
Expected: 3 passed

- [ ] **Step 5: Typecheck**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

- [ ] **Step 6: Commit**

```bash
git add agent_perimeter/_contracts.py tests/test_contracts.py
git commit -m "feat: add bok-core contract stand-ins with provenance rules"
```

---

### Task 3: ScopeFile and the fail-closed authorisation guard

**Files:**
- Create: `agent_perimeter/model/__init__.py`
- Create: `agent_perimeter/model/scope.py`
- Test: `tests/model/__init__.py`
- Test: `tests/model/test_scope.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ScopeFile` (Pydantic model: `target`, `authorising_party`, `authorised_on`, `attestation`, `expires_on`); `AuthorizationRequired(Exception)`; `require_scope(scope: ScopeFile | None, *, check_id: str, target: str, today: date) -> None` which raises unless a valid, unexpired, target-matching scope is supplied. Tasks 10 and 11 call `require_scope`.

**Why this is Task 3 and not Task 8:** this is hard constraint 1 and DoD item 3. Unauthorised probing is a criminal-liability question, not a style preference. The guard exists before anything that could probe.

- [ ] **Step 1: Create package markers**

```bash
mkdir -p agent_perimeter/model tests/model
touch agent_perimeter/model/__init__.py tests/model/__init__.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/model/test_scope.py
from datetime import date

import pytest

from agent_perimeter.model.scope import (
    AuthorizationRequired,
    ScopeFile,
    require_scope,
)

TODAY = date(2026, 9, 1)
TARGET = "https://mcp.example.test"


def _scope(**overrides: object) -> ScopeFile:
    base: dict[str, object] = {
        "target": TARGET,
        "authorising_party": "Example Ltd, Head of Security",
        "authorised_on": date(2026, 8, 30),
        "attestation": "I authorise active security probing of the named target.",
        "expires_on": date(2026, 9, 30),
    }
    base.update(overrides)
    return ScopeFile(**base)  # type: ignore[arg-type]


def test_missing_scope_refuses() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(None, check_id="active.ssrf", target=TARGET, today=TODAY)
    assert "active.ssrf" in str(exc.value)
    assert "scope file" in str(exc.value)


def test_expired_scope_refuses_and_names_the_field() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(expires_on=date(2026, 8, 31)),
            check_id="active.ssrf",
            target=TARGET,
            today=TODAY,
        )
    assert "expires_on" in str(exc.value)


def test_target_mismatch_refuses() -> None:
    with pytest.raises(AuthorizationRequired) as exc:
        require_scope(
            _scope(), check_id="active.ssrf", target="https://other.example.test", today=TODAY
        )
    assert "target" in str(exc.value)


def test_valid_scope_permits() -> None:
    require_scope(_scope(), check_id="active.ssrf", target=TARGET, today=TODAY)


def test_blank_attestation_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="attestation"):
        _scope(attestation="   ")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/model/test_scope.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.model.scope'`

- [ ] **Step 4: Write the minimal implementation**

```python
# agent_perimeter/model/scope.py
"""Authorisation for active probing. Fails closed, always.

Hard constraint 1: the tool refuses active probes without a scope file naming
the target, the authorising party and a date. Unauthorised probing is a
criminal-liability question in most jurisdictions, not a style preference.
"""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, ValidationInfo, field_validator


class AuthorizationRequired(Exception):
    """Raised when an active check is attempted without valid authorisation."""


class ScopeFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str
    authorising_party: str
    authorised_on: date
    attestation: str
    expires_on: date | None = None

    @field_validator("target", "authorising_party", "attestation")
    @classmethod
    def _must_not_be_blank(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            msg = f"{info.field_name} must not be blank"
            raise ValueError(msg)
        return value


def require_scope(
    scope: ScopeFile | None,
    *,
    check_id: str,
    target: str,
    today: date,
) -> None:
    """Raise unless `scope` authorises active probing of `target` on `today`.

    The message names the specific missing or failing field, because an error
    that does not say what to do next is not an error message.
    """
    if scope is None:
        msg = (
            f"Check {check_id} is an active probe and no scope file was supplied. "
            f"Attach a scope file naming target, authorising_party, authorised_on "
            f"and attestation."
        )
        raise AuthorizationRequired(msg)

    if scope.target != target:
        msg = (
            f"Check {check_id} refused: scope file target is {scope.target!r} "
            f"but the scan target is {target!r}. Field: target."
        )
        raise AuthorizationRequired(msg)

    if scope.expires_on is not None and scope.expires_on < today:
        msg = (
            f"Check {check_id} refused: authorisation lapsed on {scope.expires_on}. "
            f"Field: expires_on."
        )
        raise AuthorizationRequired(msg)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/model/test_scope.py -v --no-cov`
Expected: 5 passed

- [ ] **Step 6: Typecheck and commit**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

```bash
git add agent_perimeter/model tests/model
git commit -m "feat: add ScopeFile and fail-closed authorisation guard (DoD 3)"
```

---

### Task 4: Containerised stdio launcher

**Files:**
- Create: `agent_perimeter/transport/__init__.py`
- Create: `agent_perimeter/transport/base.py`
- Create: `agent_perimeter/transport/stdio.py`
- Create: `agent_perimeter/transport/seccomp.json`
- Test: `tests/transport/__init__.py`
- Test: `tests/transport/test_stdio.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Transport` Protocol with `request(method: str, params: dict[str, object] | None = None) -> dict[str, object]` and `close() -> None`; `TransportError(Exception)` carrying an optional JSON-RPC `code: int | None`; `LaunchSpec(image, command, timeout_s, allow_network, memory, cpus, env, hardened_seccomp, launch_phase)`; `ContainmentError(TransportError)`; `docker_args(spec) -> list[str]`; `build_two_phase_image(install_command, *, tag, base_image) -> str`; `StdioTransport(spec)` — one container for the whole scan, not one per request. Tasks 5, 8 and 11 depend on these.

**Why this is built before any check:** B3. Launching a stdio MCP server means executing an arbitrary binary from an untrusted source. Unsandboxed, the first malicious server owns the machine and every credential on it.

- [ ] **Step 1: Create package markers**

```bash
mkdir -p agent_perimeter/transport tests/transport
touch agent_perimeter/transport/__init__.py tests/transport/__init__.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/transport/test_stdio.py
import pytest

from agent_perimeter.transport.stdio import SECCOMP_PROFILE, LaunchSpec, docker_args, two_phase_dockerfile


def test_docker_args_enforce_every_containment_control() -> None:
    args = docker_args(LaunchSpec(image="python:3.12-slim", command=["python", "-c", "pass"]))
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--user 65534:65534" in joined
    assert "--cap-drop ALL" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--memory 256m" in joined
    assert "--pids-limit 128" in joined
    assert "--tmpfs /tmp" in joined
    assert "--ulimit nofile" in joined
    assert "HOME=/tmp" in joined
    assert " -v " not in joined, "no host mounts, ever"


def test_docker_default_seccomp_applies_unless_hardened_is_requested() -> None:
    """Docker's own default profile blocks the dangerous set (mount, ptrace,
    bpf, kexec, reboot, keyring calls) and is exercised across every
    architecture. The hand-written allowlist in seccomp.json is missing
    syscalls CPython needs (unlinkat, rt_sigsuspend, restart_syscall,
    membarrier, clock_nanosleep, socketpair, mremap, eventfd2, renameat2,
    ftruncate, getgroups, sched_getparam) and covers only x86_64 — so it is
    opt-in, never the default.
    """
    default = " ".join(docker_args(LaunchSpec(image="i", command=["c"])))
    assert "seccomp=" not in default

    hardened = " ".join(docker_args(LaunchSpec(image="i", command=["c"], hardened_seccomp=True)))
    assert f"seccomp={SECCOMP_PROFILE}" in hardened


def test_allow_network_is_explicit_and_off_by_default() -> None:
    default = " ".join(docker_args(LaunchSpec(image="i", command=["c"])))
    assert "--network none" in default

    permitted = " ".join(docker_args(LaunchSpec(image="i", command=["c"], allow_network=True)))
    assert "--network none" not in permitted


def test_zero_timeout_is_rejected() -> None:
    with pytest.raises(ValueError, match="timeout_s"):
        LaunchSpec(image="i", command=["c"], timeout_s=0)


def test_two_phase_dockerfile_installs_with_network_at_build_time() -> None:
    """npx -y <pkg> and uvx <pkg> both need network on every launch to
    resolve the package. Materialising the install into an image at build
    time — the one step that runs with network — is what lets the actual
    scan run every request with --network none."""
    dockerfile = two_phase_dockerfile(["npm", "install", "-g", "@scope/server"], "node:20-slim")
    assert dockerfile.startswith("FROM node:20-slim\n")
    assert "RUN npm install -g @scope/server" in dockerfile
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/transport/test_stdio.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.transport.stdio'`

- [ ] **Step 4: Write `base.py`**

```python
# agent_perimeter/transport/base.py
from __future__ import annotations

from typing import Protocol


class TransportError(Exception):
    """The transport could not complete a request.

    `code` carries the JSON-RPC error code when one was observed (e.g. from
    a `server/discover` failure) — 2026-07-28 allocates specific codes as a
    deterministic revision fingerprint (Task 8), so it travels with the
    exception rather than being lost in a formatted message string.
    """

    def __init__(self, message: str, *, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class Transport(Protocol):
    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Send one JSON-RPC request and return its result object."""
        ...

    def close(self) -> None: ...
```

- [ ] **Step 5: Write `seccomp.json` — an optional, hardened profile, not the default**

Docker's own default seccomp profile already blocks the dangerous set
(`mount`, `ptrace`, `bpf`, `kexec`, `reboot`, keyring calls) and is exercised
across every architecture Docker runs on. This hand-written allowlist is
kept only for operators who explicitly want a stricter one via
`hardened_seccomp=True` — it must not be the default, because a missing
syscall surfaces as a confusing `EPERM` indistinguishable from a protocol
error, and the original list omitted syscalls CPython itself needs
(`unlinkat`, `rt_sigsuspend`, `restart_syscall`, `membarrier`,
`clock_nanosleep`, `socketpair`, `mremap`, `eventfd2`, `renameat2`,
`ftruncate`, `getgroups`, `sched_getparam`) and covered only `x86_64`,
breaking every ARM host (Apple Silicon, ARM CI runners).

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]
    },
    {
      "architecture": "SCMP_ARCH_AARCH64",
      "subArchitectures": ["SCMP_ARCH_ARM"]
    }
  ],
  "syscalls": [
    {
      "names": [
        "accept4", "arch_prctl", "brk", "capget", "capset", "chdir", "clock_getres",
        "clock_gettime", "clock_nanosleep", "clone", "clone3", "close", "connect",
        "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl", "epoll_pwait",
        "eventfd2", "execve", "exit", "exit_group", "faccessat", "faccessat2",
        "fchdir", "fcntl", "fstat", "fstatfs", "ftruncate", "futex", "getcwd",
        "getdents64", "getegid", "geteuid", "getgid", "getgroups", "getpid",
        "getppid", "getrandom", "getrlimit", "gettid", "getuid", "ioctl", "lseek",
        "madvise", "membarrier", "mmap", "mprotect", "mremap", "munmap",
        "nanosleep", "newfstatat", "openat", "pipe2", "poll", "ppoll", "prctl",
        "pread64", "prlimit64", "pwrite64", "read", "readlink", "readlinkat",
        "renameat2", "restart_syscall", "rseq", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "rt_sigsuspend", "sched_getaffinity", "sched_getparam",
        "sched_yield", "set_robust_list", "set_tid_address", "setgid",
        "setgroups", "setuid", "sigaltstack", "socket", "socketpair", "statfs",
        "statx", "sysinfo", "tgkill", "uname", "unlinkat", "wait4", "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

- [ ] **Step 6: Write `stdio.py`**

```python
# agent_perimeter/transport/stdio.py
"""Containerised launcher for stdio MCP servers.

Scanning a stdio MCP server means executing an untrusted binary. Every launch
is confined: non-root, read-only rootfs, no network unless explicitly
required, tmpfs scratch, capability drop, no-new-privileges, memory/CPU/PID
caps, a hard wall-clock budget, and no host mounts under any circumstances.

One container runs for the *whole scan*, not one per JSON-RPC request. A
fresh container per call would discard whatever handle state the server
minted on an earlier request — 2026-07-28 requires cross-request state to be
an explicit server-minted handle, so a multi-step probe only works if every
call in it reaches the same process, and at eval-harness scale (~4,000
launches with MCPTox) a container per request is not runnable in CI either.
Requests are newline-delimited JSON-RPC framed over a persistent
stdin/stdout pipe; the container is torn down once, at the end of the scan.

Docker's *default* seccomp profile is applied unless `hardened_seccomp=True`
is set — see `seccomp.json`'s own note on why the hand-written allowlist is
opt-in rather than the default.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from agent_perimeter.transport.base import TransportError

SECCOMP_PROFILE = Path(__file__).parent / "seccomp.json"


class ContainmentError(TransportError):
    """The sandboxed process breached or exceeded its confinement."""


@dataclass(frozen=True)
class LaunchSpec:
    image: str
    command: list[str]
    timeout_s: int = 300  # hard wall-clock budget for the whole scan, not one request
    allow_network: bool = False
    memory: str = "256m"
    cpus: str = "0.5"
    env: dict[str, str] = field(default_factory=dict)
    hardened_seccomp: bool = False  # opt in to the hand-written allowlist; default is Docker's own
    launch_phase: Literal["direct", "two_phase_build"] = "direct"
    """Which launch path produced `image` — recorded so a scan can report
    which targets needed the npx/uvx two-phase build (see
    `build_two_phase_image` below and revision §7.3)."""

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            msg = "timeout_s must be greater than zero"
            raise ValueError(msg)


def docker_args(spec: LaunchSpec) -> list[str]:
    """Build the `docker run` argument list. No host mounts are ever emitted."""
    args = [
        "docker", "run", "--rm", "-i",
        "--user", "65534:65534",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--env", "HOME=/tmp",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", spec.memory,
        "--cpus", spec.cpus,
        "--pids-limit", "128",
        "--ulimit", "nofile=1024:1024",
    ]
    if spec.hardened_seccomp:
        args += ["--security-opt", f"seccomp={SECCOMP_PROFILE}"]
    if not spec.allow_network:
        args += ["--network", "none"]
    for key, value in spec.env.items():
        args += ["--env", f"{key}={value}"]
    args.append(spec.image)
    args += spec.command
    return args


def two_phase_dockerfile(install_command: list[str], base_image: str) -> str:
    """A Dockerfile that fetches the package at build time, with network.

    `npx -y @scope/server` and `uvx some-server` both need network on every
    launch to resolve the package — the most common stdio invocation in the
    wild, and unscannable under `--network none` without this. `docker
    build` runs with the host's network regardless of the flags `docker run`
    will use later, so materialising the package here, once, is what lets
    every actual scan request run with `--network none`.
    """
    install = " ".join(shlex.quote(part) for part in install_command)
    return f"FROM {base_image}\nRUN {install}\n"


def build_two_phase_image(install_command: list[str], *, tag: str, base_image: str) -> str:
    """Build step only — runs WITH network. The resulting image needs none.

    Not exercised in CI without network access to the package registry.
    Tag the `LaunchSpec` that uses the resulting image with
    `launch_phase="two_phase_build"` so a scan can record which targets
    needed it — "we could not scan npx servers" is a coverage hole that
    should be visible, not silent (revision §7.3).
    """
    with tempfile.TemporaryDirectory() as build_dir:
        Path(build_dir, "Dockerfile").write_text(
            two_phase_dockerfile(install_command, base_image), encoding="utf-8"
        )
        subprocess.run(
            ["docker", "build", "-t", tag, build_dir],
            check=True,
            capture_output=True,
        )
    return tag


class StdioTransport:
    """One long-lived container for the whole scan.

    `docker run -i` is started once, on construction. Every `request()`
    writes one newline-delimited JSON-RPC line to its stdin and reads one
    back from its stdout — the framing the fixture, and every real stdio
    server, already speaks. A `threading.Timer` enforces the scan's hard
    wall-clock budget by killing the process; a blocked read then sees EOF
    and raises `ContainmentError` rather than hanging forever.
    """

    def __init__(self, spec: LaunchSpec) -> None:
        self._spec = spec
        self._next_id = 1
        self._deadline_exceeded = False
        self._process: subprocess.Popen[str] = subprocess.Popen(
            docker_args(spec),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._timer = threading.Timer(spec.timeout_s, self._on_deadline)
        self._timer.daemon = True
        self._timer.start()

    @property
    def launch_phase(self) -> str:
        return self._spec.launch_phase

    def _on_deadline(self) -> None:
        self._deadline_exceeded = True
        self._process.kill()

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        if self._process.stdin is None or self._process.stdout is None:
            msg = "Container process has no stdio pipes."
            raise TransportError(msg)

        request_id = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        try:
            self._process.stdin.write(payload + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            msg = f"Container stopped accepting input: {exc}"
            raise ContainmentError(msg) from exc

        line = self._process.stdout.readline()
        if not line:
            if self._deadline_exceeded:
                msg = f"Container exceeded its {self._spec.timeout_s}s limit and was killed."
                raise ContainmentError(msg)
            stderr = self._process.stderr.read()[:400] if self._process.stderr else ""
            msg = (
                f"No JSON-RPC response for {method}. Container exited "
                f"(code {self._process.returncode}). stderr: {stderr}"
            )
            raise TransportError(msg)

        message = json.loads(line)
        if "error" in message:
            error = message["error"]
            code = error.get("code") if isinstance(error, dict) else None
            msg = f"Server returned an error for {method}: {error}"
            raise TransportError(msg, code=code if isinstance(code, int) else None)
        result: dict[str, object] = message.get("result", {})
        return result

    def close(self) -> None:
        self._timer.cancel()
        if self._process.poll() is None:
            if self._process.stdin is not None:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/transport/test_stdio.py -v --no-cov`
Expected: 5 passed

- [ ] **Step 8: Prove one container serves a multi-request sequence (Revision §7.1)**

A per-request container cannot carry state a server minted on an earlier
call. Prove the replacement does, with a tiny in-process counter — no image
build required, so this runs anywhere Docker does.

```python
# tests/transport/test_stdio.py (append to the same file)
import shutil

import pytest

from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport

_COUNTING_SERVER = (
    "import json, sys\n"
    "count = 0\n"
    "for line in sys.stdin:\n"
    "    if not line.strip():\n"
    "        continue\n"
    "    count += 1\n"
    "    msg = json.loads(line)\n"
    "    reply = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {'count': count}}\n"
    "    print(json.dumps(reply), flush=True)\n"
)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")
def test_one_container_serves_a_multi_request_sequence() -> None:
    """The container is not restarted between calls, so state accumulates —
    exactly what a server-minted handle needs to survive across requests."""
    transport = StdioTransport(
        LaunchSpec(image="python:3.12-slim", command=["python3", "-c", _COUNTING_SERVER])
    )
    try:
        first = transport.request("ping")
        second = transport.request("ping")
        third = transport.request("ping")
    finally:
        transport.close()

    assert (first["count"], second["count"], third["count"]) == (1, 2, 3)
```

Run: `uv run pytest tests/transport/test_stdio.py -v --no-cov`
Expected: 6 passed (or 5 passed, 1 skipped if Docker is unavailable).

- [ ] **Step 9: Typecheck and commit**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

```bash
git add agent_perimeter/transport tests/transport
git commit -m "feat: add containerised stdio launcher, one container per scan"
```

---

### Task 5: Sandbox containment test suite

**Files:**
- Create: `tests/fixtures/hostile/Dockerfile`
- Create: `tests/fixtures/hostile/hostile.py`
- Test: `tests/transport/test_containment.py`

**Interfaces:**
- Consumes: `LaunchSpec`, `StdioTransport`, `ContainmentError`, `docker_args` from Task 4.
- Produces: no library code. Produces DoD item 4 — proof of containment.

**Why this is separate from Task 4:** a reviewer can accept the launcher's argument construction while rejecting the containment evidence, or the reverse. These are different claims and deserve separate gates.

- [ ] **Step 1: Write the hostile fixture**

```python
# tests/fixtures/hostile/hostile.py
"""A deliberately hostile MCP server used to prove containment.

Behaviour is selected by AP_HOSTILE_MODE. This file contains no secrets and no
real exploit payload: each mode attempts one boundary and reports the outcome.
"""

import os
import socket
import sys

MODE = os.environ.get("AP_HOSTILE_MODE", "none")

if MODE == "network":
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3)
        print("BREACH: network reachable", file=sys.stderr)
        sys.exit(0)
    except OSError:
        print("CONTAINED: network unreachable", file=sys.stderr)
        sys.exit(3)

elif MODE == "rootfs_write":
    try:
        with open("/etc/ap_breach", "w") as handle:
            handle.write("x")
        print("BREACH: rootfs writable", file=sys.stderr)
        sys.exit(0)
    except OSError:
        print("CONTAINED: rootfs read-only", file=sys.stderr)
        sys.exit(3)

elif MODE == "memory":
    blocks = []
    while True:
        blocks.append(bytearray(16 * 1024 * 1024))

elif MODE == "hang":
    while True:
        pass

elif MODE == "root":
    print(f"UID={os.getuid()}", file=sys.stderr)
    sys.exit(0 if os.getuid() == 0 else 3)
```

- [ ] **Step 2: Write the fixture Dockerfile**

```dockerfile
FROM python:3.12-slim
COPY hostile.py /hostile.py
ENTRYPOINT ["python", "/hostile.py"]
```

- [ ] **Step 3: Write the containment tests**

```python
# tests/transport/test_containment.py
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_perimeter.transport.stdio import (
    ContainmentError,
    LaunchSpec,
    StdioTransport,
    docker_args,
)

IMAGE = "agent-perimeter-hostile:test"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "hostile"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    subprocess.run(
        ["docker", "build", "-t", IMAGE, str(FIXTURE)], check=True, capture_output=True
    )


def _run(mode: str, timeout_s: int = 30) -> subprocess.CompletedProcess[str]:
    spec = LaunchSpec(
        image=IMAGE, command=[], env={"AP_HOSTILE_MODE": mode}, timeout_s=timeout_s
    )
    return subprocess.run(
        docker_args(spec), capture_output=True, text=True, timeout=60, check=False
    )


def test_network_is_unreachable() -> None:
    assert "CONTAINED" in _run("network").stderr


def test_rootfs_is_read_only() -> None:
    assert "CONTAINED" in _run("rootfs_write").stderr


def test_process_does_not_run_as_root() -> None:
    assert "UID=65534" in _run("root").stderr


def test_memory_bomb_is_killed() -> None:
    assert _run("memory", timeout_s=60).returncode != 0


def test_hang_hits_the_hard_timeout() -> None:
    transport = StdioTransport(
        LaunchSpec(image=IMAGE, command=[], env={"AP_HOSTILE_MODE": "hang"}, timeout_s=5)
    )
    with pytest.raises(ContainmentError, match="exceeded its 5s limit"):
        transport.request("tools/list")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/transport/test_containment.py -v --no-cov`
Expected: 5 passed.

If `test_network_is_unreachable` fails, the launcher is not applying `--network none` — stop and fix Task 4 before continuing. This is DoD item 4 and nothing downstream is safe without it.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/hostile tests/transport/test_containment.py
git commit -m "test: prove stdio containment against a hostile fixture (DoD 4)"
```

---

### Task 6: Parameterised MCP fixture server

**Files:**
- Create: `tests/fixtures/servers/server.py`
- Create: `tests/fixtures/servers/Dockerfile`
- Test: `tests/fixtures/servers/test_fixture_self.py`
- Test: `tests/transport/test_seccomp_compat.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a fixture MCP server whose protocol revision and injected flaw are selected by `AP_FIXTURE_REVISION` (`2025-11-25` | `2026-07-28`) and `AP_FIXTURE_FLAW` (`none` | `cache_scope_public` | `missing_result_type` | `param_header`). Exposes `handle(message: dict) -> dict` for in-process testing. Tasks 8 and 11 test against it; Week 2 extends the flaw matrix. Also gives Task 4's seccomp fix a real Python MCP server to prove itself against (Revision §7.2).

**Why one parameterised server and not ten:** brief §11 requires each fixture to be vulnerable to exactly one thing. Each *instance* is. Ten separate server builds would be days of work for the same guarantee.

- [ ] **Step 1: Write the fixture server**

```python
# tests/fixtures/servers/server.py
"""A parameterised MCP fixture server.

AP_FIXTURE_REVISION selects the protocol revision it speaks.
AP_FIXTURE_FLAW injects exactly one flaw. Contains no secrets.
"""

import json
import os
import sys

REVISION = os.environ.get("AP_FIXTURE_REVISION", "2026-07-28")
FLAW = os.environ.get("AP_FIXTURE_FLAW", "none")


def _tools() -> list[dict]:
    return [
        {
            "name": "read_file",
            "description": "Read a file from the local workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]


def _tools_list_result() -> dict:
    result: dict = {"tools": _tools()}
    if REVISION != "2026-07-28":
        return result

    result["resultType"] = "complete"
    result["ttlMs"] = 60000
    result["cacheScope"] = "public" if FLAW == "cache_scope_public" else "private"

    if FLAW == "missing_result_type":
        del result["resultType"]
    if FLAW == "param_header":
        result["tools"][0]["inputSchema"]["properties"]["x-mcp-header"] = {"type": "string"}
    return result


def _discover_result() -> dict:
    return {
        "resultType": "complete",
        "protocolVersions": ["2026-07-28"],
        "capabilities": {"tools": {}, "extensions": {}},
        "serverInfo": {"name": "ap-fixture", "version": "0.1.0"},
    }


def _not_found(request_id: object) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def handle(message: dict) -> dict:
    method = message.get("method")
    request_id = message.get("id")

    if method == "server/discover":
        if REVISION != "2026-07-28":
            return _not_found(request_id)
        return {"jsonrpc": "2.0", "id": request_id, "result": _discover_result()}

    if method == "initialize":
        if REVISION == "2026-07-28":
            return _not_found(request_id)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": REVISION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ap-fixture", "version": "0.1.0"},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": _tools_list_result()}

    return _not_found(request_id)


def main() -> None:
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle(json.loads(line))), flush=True)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write the Dockerfile**

```dockerfile
FROM python:3.12-slim
COPY server.py /server.py
ENTRYPOINT ["python", "/server.py"]
```

- [ ] **Step 3: Write the self-test**

```python
# tests/fixtures/servers/test_fixture_self.py
import importlib.util
from pathlib import Path
from typing import Any

import pytest

SERVER = Path(__file__).parent / "server.py"


def _load(revision: str, flaw: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AP_FIXTURE_REVISION", revision)
    monkeypatch.setenv("AP_FIXTURE_FLAW", flaw)
    spec = importlib.util.spec_from_file_location(f"fx_{revision}_{flaw}", SERVER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_modern_revision_answers_discover(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "none", monkeypatch)
    reply = mod.handle({"method": "server/discover", "id": 1})
    assert reply["result"]["protocolVersions"] == ["2026-07-28"]


def test_modern_revision_rejects_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "none", monkeypatch)
    assert "error" in mod.handle({"method": "initialize", "id": 1})


def test_legacy_revision_answers_initialize(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2025-11-25", "none", monkeypatch)
    reply = mod.handle({"method": "initialize", "id": 1})
    assert reply["result"]["protocolVersion"] == "2025-11-25"


def test_legacy_revision_rejects_discover(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2025-11-25", "none", monkeypatch)
    assert "error" in mod.handle({"method": "server/discover", "id": 1})


def test_cache_scope_flaw_is_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = _load("2026-07-28", "none", monkeypatch)
    assert clean.handle({"method": "tools/list", "id": 1})["result"]["cacheScope"] == "private"

    flawed = _load("2026-07-28", "cache_scope_public", monkeypatch)
    assert flawed.handle({"method": "tools/list", "id": 1})["result"]["cacheScope"] == "public"


def test_missing_result_type_flaw_is_injectable(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load("2026-07-28", "missing_result_type", monkeypatch)
    assert "resultType" not in mod.handle({"method": "tools/list", "id": 1})["result"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/fixtures/servers/test_fixture_self.py -v --no-cov`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/servers
git commit -m "test: add parameterised MCP fixture server with revision and flaw matrix"
```

- [ ] **Step 6: Prove the sandbox runs this real server under both seccomp profiles (Revision §7.2)**

Task 4 makes Docker's default seccomp profile the default and keeps the
hand-written allowlist in `seccomp.json` as an opt-in `hardened_seccomp`
flag. Prove a real Python MCP server — this fixture — completes a request
under both, so a missing syscall is caught here rather than reported later
as a false finding about the target.

```python
# tests/transport/test_seccomp_compat.py
import shutil
import subprocess
from pathlib import Path

import pytest

from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport

IMAGE = "agent-perimeter-fixture:test"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "servers"

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker unavailable")


@pytest.fixture(scope="module", autouse=True)
def build_image() -> None:
    subprocess.run(
        ["docker", "build", "-t", IMAGE, str(FIXTURE)], check=True, capture_output=True
    )


@pytest.mark.parametrize("hardened_seccomp", [False, True])
def test_server_completes_a_request_under_the_profile(hardened_seccomp: bool) -> None:
    transport = StdioTransport(
        LaunchSpec(
            image=IMAGE,
            command=[],
            env={"AP_FIXTURE_REVISION": "2026-07-28", "AP_FIXTURE_FLAW": "none"},
            hardened_seccomp=hardened_seccomp,
        )
    )
    try:
        result = transport.request("server/discover")
    finally:
        transport.close()
    assert result["protocolVersions"] == ["2026-07-28"]
```

Run: `uv run pytest tests/transport/test_seccomp_compat.py -v --no-cov`
Expected: 2 passed (skipped if Docker is unavailable). If the
`hardened_seccomp=True` case fails with an `EPERM`-shaped error while the
default case passes, `seccomp.json` is still missing a syscall — fix the
allowlist, do not weaken this test.

- [ ] **Step 7: Commit**

```bash
git add tests/transport/test_seccomp_compat.py
git commit -m "test: prove a real Python MCP server runs under both seccomp profiles"
```

---

### Task 7: Feature model and revision bundles

**Files:**
- Create: `agent_perimeter/model/feature.py`
- Create: `agent_perimeter/transport/features.yaml`
- Test: `tests/model/test_feature.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Feature` (`StrEnum`), `Revision` (`StrEnum`), `FeatureSet = frozenset[Feature]`, `load_bundles(path: Path) -> dict[Revision, FeatureSet]`, `BUNDLES: dict[Revision, FeatureSet]`. Tasks 8, 10 and 11 consume `Feature`, `Revision` and `FeatureSet`.

**Why the mapping is YAML and not code:** approach B in spec §4.1. A future revision adds one bundle to a data file rather than editing every check declaration.

- [ ] **Step 1: Write the failing test**

```python
# tests/model/test_feature.py
from agent_perimeter.model.feature import BUNDLES, Feature, Revision


def test_modern_revision_has_discover_and_lacks_handshake() -> None:
    modern = BUNDLES[Revision.R2026_07_28]
    assert Feature.SERVER_DISCOVER in modern
    assert Feature.RESULT_TYPE in modern
    assert Feature.CACHEABLE_RESULT in modern
    assert Feature.MRTR in modern
    assert Feature.INITIALIZE_HANDSHAKE not in modern
    assert Feature.SESSION_HEADER not in modern


def test_legacy_revision_has_handshake_and_lacks_discover() -> None:
    legacy = BUNDLES[Revision.R2025_11_25]
    assert Feature.INITIALIZE_HANDSHAKE in legacy
    assert Feature.SESSION_HEADER in legacy
    assert Feature.SERVER_DISCOVER not in legacy


def test_every_revision_bundle_is_a_frozenset() -> None:
    assert all(isinstance(bundle, frozenset) for bundle in BUNDLES.values())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/model/test_feature.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.model.feature'`

- [ ] **Step 3: Write `features.yaml`**

```yaml
# Revision -> feature bundle. Adding a future revision means adding a block
# here, not editing check declarations. See spec section 4.1.
2025-11-25:
  - initialize_handshake
  - session_header
  - sse_resumability
  - subscribe_unsubscribe
2026-07-28:
  - server_discover
  - result_type
  - cacheable_result
  - mrtr
  - param_headers
  - subscriptions_listen
  - extensions
```

- [ ] **Step 4: Write `feature.py`**

```python
# agent_perimeter/model/feature.py
"""Protocol features, and the revision bundles that name sets of them.

Checks are predicated on observed features, never on a claimed version string,
so a server that implements a revision partially is handled correctly rather
than mis-scanned.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml

FEATURES_YAML = Path(__file__).parents[1] / "transport" / "features.yaml"


class Feature(StrEnum):
    """No `STATELESS_META` member: that would describe the *client's*
    request shape, not something the server does — a version-implies-feature
    proxy this design otherwise avoids. See revision §2.1."""

    SERVER_DISCOVER = "server_discover"
    RESULT_TYPE = "result_type"
    CACHEABLE_RESULT = "cacheable_result"
    MRTR = "mrtr"
    PARAM_HEADERS = "param_headers"
    SUBSCRIPTIONS_LISTEN = "subscriptions_listen"
    EXTENSIONS = "extensions"
    INITIALIZE_HANDSHAKE = "initialize_handshake"
    SESSION_HEADER = "session_header"
    SSE_RESUMABILITY = "sse_resumability"
    SUBSCRIBE_UNSUBSCRIBE = "subscribe_unsubscribe"


class Revision(StrEnum):
    R2025_11_25 = "2025-11-25"
    R2026_07_28 = "2026-07-28"


FeatureSet = frozenset[Feature]


def load_bundles(path: Path = FEATURES_YAML) -> dict[Revision, FeatureSet]:
    raw: dict[str, list[str]] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {
        Revision(revision): frozenset(Feature(name) for name in names)
        for revision, names in raw.items()
    }


BUNDLES: dict[Revision, FeatureSet] = load_bundles()
```

- [ ] **Step 5: Run test to verify it passes, then typecheck**

Run: `uv run pytest tests/model/test_feature.py -v --no-cov`
Expected: 3 passed

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

- [ ] **Step 6: Commit**

```bash
git add agent_perimeter/model/feature.py agent_perimeter/transport/features.yaml tests/model/test_feature.py
git commit -m "feat: add Feature model and revision bundles loaded from YAML"
```

---

### Task 8: Revision fingerprinter

**Files:**
- Create: `agent_perimeter/transport/revision.py`
- Test: `tests/transport/test_revision.py`

**Interfaces:**
- Consumes: `Transport`, `TransportError` (Task 4); `Feature`, `Revision`, `FeatureSet` (Task 7); `Claim`, `Method`, `Derivation` (Task 2); `handle()` from the Task 6 fixture, for the integration test only.
- Produces: `Fingerprint(revision_claimed: Revision | None, features: FeatureSet, claim: Claim, protocol_versions_advertised: tuple[str, ...], discover_error_code: int | None)` and `fingerprint(transport: Transport) -> Fingerprint`. Task 11 consumes both.

**The load-bearing behaviour:** the claimed revision and the observed feature set are established *independently*. Their disagreement is the `conformance_mismatch` finding in Week 2, which is only detectable because they are separated here. Just as load-bearing: every feature in the observed set was actually seen. None is granted just because `server/discover` succeeded or a revision was claimed — a check that needs an unobservable feature (`MRTR`, `SUBSCRIPTIONS_LISTEN`) skips honestly instead of firing on a fiction.

- [ ] **Step 1: Write the failing test**

```python
# tests/transport/test_revision.py
import importlib.util
from pathlib import Path
from typing import Any

import pytest

from agent_perimeter._contracts import Derivation, Method
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.revision import fingerprint


class FakeTransport:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        self.calls.append(method)
        if method not in self._responses:
            msg = f"Method not found: {method}"
            raise TransportError(msg)
        result: dict[str, object] = self._responses[method]
        return result

    def close(self) -> None: ...


MODERN_DISCOVER = {
    "resultType": "complete",
    "protocolVersions": ["2026-07-28"],
    "capabilities": {"tools": {}, "extensions": {}},
}
MODERN_TOOLS = {"resultType": "complete", "ttlMs": 60000, "cacheScope": "private", "tools": []}


def test_modern_server_is_fingerprinted_from_discover() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert result.revision_claimed is Revision.R2026_07_28
    assert Feature.SERVER_DISCOVER in result.features
    assert Feature.RESULT_TYPE in result.features
    assert Feature.CACHEABLE_RESULT in result.features
    assert Feature.EXTENSIONS in result.features


def test_legacy_server_falls_back_to_initialize() -> None:
    transport = FakeTransport(
        {
            "initialize": {"protocolVersion": "2025-11-25", "capabilities": {}},
            "tools/list": {"tools": []},
        }
    )
    result = fingerprint(transport)
    assert result.revision_claimed is Revision.R2025_11_25
    assert Feature.INITIALIZE_HANDSHAKE in result.features
    assert Feature.SERVER_DISCOVER not in result.features
    assert transport.calls[0] == "server/discover"


def test_claim_and_observation_can_disagree() -> None:
    """A server claiming 2026-07-28 without resultType is non-conformant.

    The fingerprinter records both without reconciling them. Week 2's
    conformance_mismatch check is what reports the disagreement.
    """
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": {"tools": []}})
    )
    assert result.revision_claimed is Revision.R2026_07_28
    assert Feature.RESULT_TYPE not in result.features
    assert Feature.CACHEABLE_RESULT not in result.features


def test_discover_alone_does_not_grant_unobservable_features() -> None:
    """MRTR and SUBSCRIPTIONS_LISTEN cannot be observed passively — the first
    needs a multi-step probe, the second an open stream. SESSION_HEADER is an
    HTTP-only property with no channel to see it through here. A server
    answering server/discover must not cause any of them to be granted.
    """
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert Feature.MRTR not in result.features
    assert Feature.SUBSCRIPTIONS_LISTEN not in result.features
    assert Feature.SESSION_HEADER not in result.features


def test_unresponsive_server_yields_unknown_revision() -> None:
    result = fingerprint(FakeTransport({"tools/list": {"tools": []}}))
    assert result.revision_claimed is None
    assert result.claim.caveat == "Server answered neither server/discover nor initialize."


def test_fingerprint_carries_a_probe_derived_claim() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert result.claim.method is Method.DETERMINISTIC
    assert result.claim.derivation is Derivation.PROBE


def test_unknown_revision_string_gets_an_honest_caveat_naming_it() -> None:
    transport = FakeTransport(
        {"server/discover": {"protocolVersions": ["2027-01-01"]}, "tools/list": {}}
    )
    result = fingerprint(transport)
    assert result.revision_claimed is None
    assert result.protocol_versions_advertised == ("2027-01-01",)
    assert "2027-01-01" in (result.claim.caveat or "")
    assert "neither" not in (result.claim.caveat or "")


def test_known_older_revision_gets_an_accurate_caveat_not_the_no_response_lie() -> None:
    """2025-06-18 predates this scanner's two recognised Revision members,
    but the server did answer — the caveat must say so, never claim silence.
    """
    transport = FakeTransport(
        {
            "initialize": {"protocolVersion": "2025-06-18", "capabilities": {}},
            "tools/list": {"tools": []},
        }
    )
    result = fingerprint(transport)
    assert result.revision_claimed is None
    assert result.protocol_versions_advertised == ("2025-06-18",)
    assert Feature.INITIALIZE_HANDSHAKE in result.features
    assert "2025-06-18" in (result.claim.caveat or "")
    assert "neither" not in (result.claim.caveat or "")


def test_discover_error_code_is_captured_for_week_2s_conformance_check() -> None:
    """-32042 is a unique fingerprint for 2025-11-25 and -32001/-32003/-32004
    fingerprint a pre-final release-candidate build (revision §2.3) — Week
    2's revision.error_code_conformance is built on this field, so Week 1
    only has to prove the code survives to the Fingerprint.
    """

    class ErroringTransport:
        def request(
            self, method: str, params: dict[str, object] | None = None
        ) -> dict[str, object]:
            if method == "server/discover":
                raise TransportError("Method not found", code=-32601)
            if method == "initialize":
                return {"protocolVersion": "2025-11-25", "capabilities": {}}
            return {"tools": []}

        def close(self) -> None: ...

    result = fingerprint(ErroringTransport())
    assert result.discover_error_code == -32601


def test_param_headers_is_observed_from_a_real_annotation_not_a_property_named_for_it() -> None:
    """x-mcp-header is an annotation inside a parameter's own schema — its
    value is the header-name suffix — not a property that happens to be
    named x-mcp-header."""
    tools_with_annotation = {
        "resultType": "complete",
        "tools": [
            {
                "name": "get_weather",
                "inputSchema": {
                    "type": "object",
                    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                },
            }
        ],
    }
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": tools_with_annotation})
    )
    assert Feature.PARAM_HEADERS in result.features


def test_param_headers_is_absent_when_no_property_carries_the_annotation() -> None:
    result = fingerprint(
        FakeTransport({"server/discover": MODERN_DISCOVER, "tools/list": MODERN_TOOLS})
    )
    assert Feature.PARAM_HEADERS not in result.features


class _InProcessTransport:
    """Adapts the Task-6 fixture's handle() into a Transport. No Docker
    required — this is what lets the integration test below run fast."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self._next_id = 1

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        request_id = self._next_id
        self._next_id += 1
        reply = self._handle(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        )
        if "error" in reply:
            code = reply["error"].get("code") if isinstance(reply["error"], dict) else None
            raise TransportError(f"{method}: {reply['error']}", code=code)
        result: dict[str, object] = reply["result"]
        return result

    def close(self) -> None: ...


FIXTURE = Path(__file__).parents[1] / "fixtures" / "servers" / "server.py"


def _load_fixture(revision: str, flaw: str, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("AP_FIXTURE_REVISION", revision)
    monkeypatch.setenv("AP_FIXTURE_FLAW", flaw)
    spec = importlib.util.spec_from_file_location(f"fx_{revision}_{flaw}", FIXTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("revision", "flaw", "expected"),
    [
        (
            "2026-07-28",
            "none",
            frozenset(
                {Feature.SERVER_DISCOVER, Feature.EXTENSIONS, Feature.RESULT_TYPE, Feature.CACHEABLE_RESULT}
            ),
        ),
        (
            "2026-07-28",
            "cache_scope_public",
            frozenset(
                {Feature.SERVER_DISCOVER, Feature.EXTENSIONS, Feature.RESULT_TYPE, Feature.CACHEABLE_RESULT}
            ),
        ),
        (
            "2026-07-28",
            "missing_result_type",
            frozenset({Feature.SERVER_DISCOVER, Feature.EXTENSIONS, Feature.CACHEABLE_RESULT}),
        ),
        (
            # The fixture's param_header flaw adds a *property named*
            # x-mcp-header rather than annotating an existing one — the
            # wrong shape per revision §1.8, left for Week 2's fixture-matrix
            # pass to correct. PARAM_HEADERS must stay absent against it:
            # this proves the detector has no false positive on that shape.
            "2026-07-28",
            "param_header",
            frozenset(
                {Feature.SERVER_DISCOVER, Feature.EXTENSIONS, Feature.RESULT_TYPE, Feature.CACHEABLE_RESULT}
            ),
        ),
        ("2025-11-25", "none", frozenset({Feature.INITIALIZE_HANDSHAKE})),
    ],
)
def test_fingerprint_against_the_real_fixture_asserts_the_feature_set_exactly(
    revision: str, flaw: str, expected: frozenset[Feature], monkeypatch: pytest.MonkeyPatch
) -> None:
    """No feature is ever asserted that the fixture did not actually
    produce. This runs the real fingerprint(), not a hand-built Fingerprint
    — the eval-harness defect the revision describes (§4.3) is exactly a
    suite that stopped doing this."""
    module = _load_fixture(revision, flaw, monkeypatch)
    result = fingerprint(_InProcessTransport(module.handle))
    assert result.features == expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/transport/test_revision.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.transport.revision'`

- [ ] **Step 3: Write the implementation**

```python
# agent_perimeter/transport/revision.py
"""Fingerprint which MCP revision a server claims, and which features it has.

There is no handshake to negotiate in 2026-07-28: `initialize` was removed and
`server/discover` is mandatory. So this does not negotiate — it observes, and
it observes the claim and the behaviour separately, on purpose.

Observe or abstain. A feature is only ever added to the observed FeatureSet
when this module actually saw evidence of it — never because a revision was
claimed, and never because some other feature happened to be present. `MRTR`
and `SUBSCRIPTIONS_LISTEN` cannot be observed passively (the first needs a
multi-step probe, the second an open stream) and are never granted here; a
check requiring either skips with `FEATURE_ABSENT`, which is the honest
outcome. `SESSION_HEADER` is an HTTP-transport property with no channel to
observe it through the generic `Transport` protocol used here, so it too is
never granted — not even over stdio, and not over HTTP either until a
transport exposes response headers to this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.model.feature import Feature, FeatureSet, Revision
from agent_perimeter.transport.base import Transport, TransportError

# Widely-deployed revisions this scanner has no Revision member for. Naming
# them lets an unparseable claim carry an honest, specific caveat instead of
# the generic "no response at all" one (revision §2.2).
KNOWN_OLDER_REVISIONS = ("2025-06-18", "2025-03-26")


@dataclass(frozen=True)
class Fingerprint:
    revision_claimed: Revision | None
    features: FeatureSet
    claim: Claim
    protocol_versions_advertised: tuple[str, ...] = ()
    """The full `protocolVersions` (or single `protocolVersion`) the server
    sent, whether or not any entry parsed to a known `Revision`."""
    discover_error_code: int | None = None
    """The JSON-RPC error code observed when `server/discover` failed, if
    any. Week 2's `revision.error_code_conformance` is built on this field."""


def _highest_known(versions: tuple[str, ...]) -> Revision | None:
    """The highest *known* advertised revision, not the first — a server
    advertising both must not be recorded as the older one (revision §2.2).
    """
    known_values = {r.value for r in Revision}
    known = [Revision(v) for v in versions if v in known_values]
    return max(known) if known else None


def _revision_caveat(
    versions: tuple[str, ...], *, discover_answered: bool, initialize_answered: bool
) -> str | None:
    if not versions:
        if discover_answered or initialize_answered:
            return "Server answered but sent no parseable protocol version."
        return "Server answered neither server/discover nor initialize."
    older = [v for v in versions if v in KNOWN_OLDER_REVISIONS]
    if older:
        known = ", ".join(r.value for r in Revision)
        return f"Server claims protocol revision {older[0]!r}, which predates the revisions this scanner recognises ({known})."
    return f"Server claims an unrecognised protocol revision: {list(versions)!r}."


def _claimed_revision(
    transport: Transport,
) -> tuple[Revision | None, set[Feature], tuple[str, ...], int | None]:
    """Try server/discover, falling back to initialize.

    Returns (revision, observed_features, advertised_versions,
    discover_error_code).
    """
    observed: set[Feature] = set()
    discover_error_code: int | None = None

    try:
        discover: dict[str, object] | None = transport.request("server/discover")
    except TransportError as exc:
        discover = None
        discover_error_code = exc.code

    if discover is not None:
        observed.add(Feature.SERVER_DISCOVER)
        capabilities = discover.get("capabilities")
        if isinstance(capabilities, dict) and "extensions" in capabilities:
            observed.add(Feature.EXTENSIONS)
        versions_raw = discover.get("protocolVersions")
        versions = tuple(str(v) for v in versions_raw) if isinstance(versions_raw, list) else ()
        return _highest_known(versions), observed, versions, discover_error_code

    try:
        initialized = transport.request("initialize")
    except TransportError:
        return None, observed, (), discover_error_code

    observed.add(Feature.INITIALIZE_HANDSHAKE)
    version = initialized.get("protocolVersion")
    versions = (str(version),) if version is not None else ()
    return _highest_known(versions), observed, versions, discover_error_code


def _has_header_annotation(tool: object) -> bool:
    """PARAM_HEADERS is observed, not inferred: does any parameter's own
    schema carry an `x-mcp-header` annotation (its value the header-name
    suffix)? A property merely *named* `x-mcp-header` does not count."""
    if not isinstance(tool, dict):
        return False
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    return any(
        isinstance(prop_schema, dict) and "x-mcp-header" in prop_schema
        for prop_schema in properties.values()
    )


def _observed_features(transport: Transport) -> set[Feature]:
    observed: set[Feature] = set()
    try:
        listing = transport.request("tools/list")
    except TransportError:
        return observed

    if "resultType" in listing:
        observed.add(Feature.RESULT_TYPE)
    if "ttlMs" in listing or "cacheScope" in listing:
        observed.add(Feature.CACHEABLE_RESULT)

    tools = listing.get("tools")
    if isinstance(tools, list) and any(_has_header_annotation(tool) for tool in tools):
        observed.add(Feature.PARAM_HEADERS)

    return observed


def fingerprint(transport: Transport) -> Fingerprint:
    """Establish the claimed revision and the observed features, independently."""
    claimed, from_claim, versions, discover_error_code = _claimed_revision(transport)
    features = from_claim | _observed_features(transport)

    caveat = None
    if claimed is None:
        caveat = _revision_caveat(
            versions,
            discover_answered=Feature.SERVER_DISCOVER in features,
            initialize_answered=Feature.INITIALIZE_HANDSHAKE in features,
        )

    claim = Claim(
        value=claimed.value if claimed is not None else None,
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime.now(UTC),
        caveat=caveat,
    )
    return Fingerprint(
        revision_claimed=claimed,
        features=frozenset(features),
        claim=claim,
        protocol_versions_advertised=versions,
        discover_error_code=discover_error_code,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/transport/test_revision.py -v --no-cov`
Expected: 15 passed

- [ ] **Step 5: Typecheck and commit**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

```bash
git add agent_perimeter/transport/revision.py tests/transport/test_revision.py
git commit -m "feat: fingerprint claimed revision and observed features independently, observe-or-abstain"
```

---

### Task 9: Streamable HTTP transport

**Files:**
- Create: `agent_perimeter/transport/streamable_http.py`
- Test: `tests/transport/test_streamable_http.py`

**Interfaces:**
- Consumes: `TransportError` (Task 4).
- Produces: `StreamableHttpTransport(url: str, *, timeout_s: float = 30.0, contact_url: str)` implementing `Transport`. Task 11 selects it when the target is a URL.

**Spec detail:** 2026-07-28 requires `_meta` nested inside `params` (not a sibling of it) and an `MCP-Protocol-Version` header on every POST whose value matches `_meta`'s protocol version — a mismatch is a `400` + `HeaderMismatch` (`-32020`). `Mcp-Name` is sourced from `params.name` or `params.uri` and sent only for `tools/call`, `resources/read`, `prompts/get` — never on `tools/list`. `Mcp-Method` always equals `method`. There is no `Mcp-Session-Id` — it was removed. A response MAY arrive as `text/event-stream` instead of a single JSON body. The user agent carries a contact URL, per B10.

- [ ] **Step 1: Write the failing test**

```python
# tests/transport/test_streamable_http.py
import json

import httpx
import pytest

from agent_perimeter.transport.base import TransportError
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

CONTACT = "https://example.test/agent-perimeter"
PROTOCOL_VERSION = "2026-07-28"


def _transport(handler: object) -> StreamableHttpTransport:
    transport = StreamableHttpTransport("https://mcp.example.test/rpc", contact_url=CONTACT)
    transport._client = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return transport


def test_meta_is_nested_inside_params_not_a_sibling() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "_meta" not in seen
    params = seen["params"]
    assert isinstance(params, dict)
    meta = params["_meta"]
    assert isinstance(meta, dict)
    assert meta["io.modelcontextprotocol/protocolVersion"] == PROTOCOL_VERSION
    assert "io.modelcontextprotocol/clientCapabilities" in meta


def test_protocol_version_header_matches_the_meta_value() -> None:
    seen_headers: dict[str, str] = {}
    seen_body: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        seen_body.update(json.loads(request.content))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    params = seen_body["params"]
    assert isinstance(params, dict)
    meta = params["_meta"]
    assert isinstance(meta, dict)
    assert seen_headers["mcp-protocol-version"] == meta["io.modelcontextprotocol/protocolVersion"]


def test_mcp_method_equals_the_request_method() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("resources/list")
    assert seen["mcp-method"] == "resources/list"


def test_mcp_name_present_only_for_the_three_named_methods_and_sourced_from_params() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "mcp-name" not in seen

    _transport(handler).request("tools/call", {"name": "read_file"})
    assert seen["mcp-name"] == "read_file"

    _transport(handler).request("resources/read", {"uri": "file:///x"})
    assert seen["mcp-name"] == "file:///x"


def test_no_session_header_is_ever_sent() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    _transport(handler).request("tools/list")
    assert "mcp-session-id" not in seen
    assert CONTACT in seen["user-agent"]


def test_sse_response_is_parsed_from_its_final_data_event() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = 'event: message\ndata: {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}\n\n'
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    result = _transport(handler).request("tools/list")
    assert result == {"tools": []}


def test_json_rpc_error_is_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}
        )

    with pytest.raises(TransportError, match="nope") as excinfo:
        _transport(handler).request("server/discover")
    assert excinfo.value.code == -32601


def test_http_error_status_is_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    with pytest.raises(TransportError, match="503"):
        _transport(handler).request("tools/list")


def test_modern_header_mismatch_error_code_is_captured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32020, "message": "HeaderMismatch"}},
        )

    with pytest.raises(TransportError) as excinfo:
        _transport(handler).request("tools/list")
    assert excinfo.value.code == -32020
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/transport/test_streamable_http.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.transport.streamable_http'`

- [ ] **Step 3: Write the implementation**

```python
# agent_perimeter/transport/streamable_http.py
"""Streamable HTTP transport for MCP 2026-07-28.

Protocol-level sessions and the Mcp-Session-Id header were removed in this
revision, so nothing here carries session state. `_meta` lives inside
`params`, not beside it. Every POST carries an `MCP-Protocol-Version` header
matching `_meta`'s protocol version — a server MUST reject a mismatch with
`400` + `HeaderMismatch` (`-32020`). `Mcp-Method` always equals `method`;
`Mcp-Name` is sourced from the request's own `params.name` or `params.uri`
and sent only for `tools/call`, `resources/read`, `prompts/get` — sending it
on every request is itself the header/body mismatch a conforming server
rejects. A response MAY arrive as `text/event-stream` instead of a single
JSON body; the final `data:` event is the JSON-RPC response.
"""

from __future__ import annotations

import json

import httpx

from agent_perimeter.transport.base import TransportError

CLIENT_NAME = "agent-perimeter"
CLIENT_VERSION = "0.1.0"
PROTOCOL_VERSION = "2026-07-28"
NAMED_METHODS = {"tools/call", "resources/read", "prompts/get"}


def _mcp_name(method: str, params: dict[str, object] | None) -> str | None:
    """Mcp-Name is required only for the three named methods, sourced from
    the request's own params — never the client's own name."""
    if method not in NAMED_METHODS or not params:
        return None
    name = params.get("name", params.get("uri"))
    return str(name) if name is not None else None


def _error_code(response: httpx.Response) -> int | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, int) else None


def _parse_sse(text: str) -> dict[str, object]:
    """A server MAY answer any request with an SSE stream. Take the final
    `data:` event as the JSON-RPC response."""
    data_lines = [
        line[len("data:") :].strip() for line in text.splitlines() if line.startswith("data:")
    ]
    if not data_lines:
        msg = "SSE response contained no data: event"
        raise TransportError(msg)
    result: dict[str, object] = json.loads(data_lines[-1])
    return result


def _parse_body(response: httpx.Response) -> dict[str, object]:
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        return _parse_sse(response.text)
    result: dict[str, object] = response.json()
    return result


class StreamableHttpTransport:
    def __init__(self, url: str, *, timeout_s: float = 30.0, contact_url: str) -> None:
        self._url = url
        self._client = httpx.Client(timeout=timeout_s)
        self._contact_url = contact_url

    def request(
        self, method: str, params: dict[str, object] | None = None
    ) -> dict[str, object]:
        request_params = dict(params or {})
        request_params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": CLIENT_NAME,
                "version": CLIENT_VERSION,
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": request_params,
        }
        headers = {
            "Mcp-Method": method,
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION} (+{self._contact_url})",
        }
        name = _mcp_name(method, params)
        if name is not None:
            headers["Mcp-Name"] = name

        response = self._client.post(self._url, json=body, headers=headers)
        if response.status_code >= 400:
            msg = f"{self._url} returned {response.status_code} for {method}."
            raise TransportError(msg, code=_error_code(response))

        message = _parse_body(response)
        if "error" in message:
            error = message["error"]
            code = error.get("code") if isinstance(error, dict) else None
            msg = f"Server returned an error for {method}: {error}"
            raise TransportError(msg, code=code if isinstance(code, int) else None)
        result: dict[str, object] = message.get("result", {})
        return result

    def close(self) -> None:
        self._client.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/transport/test_streamable_http.py -v --no-cov`
Expected: 9 passed

- [ ] **Step 5: Typecheck and commit**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

```bash
git add agent_perimeter/transport/streamable_http.py tests/transport/test_streamable_http.py
git commit -m "fix: nest _meta in params, send MCP-Protocol-Version, scope Mcp-Name, parse SSE"
```

---

### Task 10: Check protocol and feature-predicate registry

**Files:**
- Create: `agent_perimeter/checks/__init__.py`
- Create: `agent_perimeter/checks/base.py`
- Create: `agent_perimeter/checks/registry.py`
- Test: `tests/checks/__init__.py`
- Test: `tests/checks/test_registry.py`

**Interfaces:**
- Consumes: `Feature`, `FeatureSet` (Task 7); `ScopeFile`, `require_scope`, `AuthorizationRequired` (Task 3); `Severity` (Task 2).
- Produces: `Check` Protocol (attributes `id`, `cwe`, `taxonomy_refs`, `severity`, `requires_auth`, `requires_model`, `requires_features`; method `run(context) -> list[object]`); `SkipReason` (`StrEnum`); `Skipped(check_id, reason, detail)`; `applicable(checks, features, *, scope, target, today, models_available=True) -> tuple[list[Check], list[Skipped]]`; `summarise_skips(skipped) -> str`. Every Week 2 check implements `Check`.

**The rule that matters:** `applicable` returns skipped checks *explicitly*, never silently drops them. A security tool that quietly stops running a check is worse than one that never had it.

- [ ] **Step 1: Create package markers**

```bash
mkdir -p agent_perimeter/checks tests/checks
touch agent_perimeter/checks/__init__.py tests/checks/__init__.py
```

- [ ] **Step 2: Write the failing test**

```python
# tests/checks/test_registry.py
from dataclasses import dataclass
from datetime import date

from agent_perimeter._contracts import Severity
from agent_perimeter.checks.registry import SkipReason, applicable, summarise_skips
from agent_perimeter.model.feature import Feature
from agent_perimeter.model.scope import ScopeFile

TODAY = date(2026, 9, 1)
TARGET = "https://mcp.example.test"

SCOPE = ScopeFile(
    target=TARGET,
    authorising_party="Example Ltd",
    authorised_on=date(2026, 8, 30),
    attestation="I authorise active probing.",
)


@dataclass(frozen=True)
class FakeCheck:
    id: str
    requires_features: frozenset[Feature] = frozenset()
    requires_auth: bool = False
    requires_model: bool = False
    cwe: str = "CWE-000"
    severity: Severity = Severity.INFO
    taxonomy_refs: tuple[str, ...] = ()

    def run(self, context: object) -> list[object]:
        return []


MODERN = frozenset({Feature.SERVER_DISCOVER, Feature.CACHEABLE_RESULT})


def test_check_runs_when_its_features_are_present() -> None:
    check = FakeCheck("revision.cache_scope", frozenset({Feature.CACHEABLE_RESULT}))
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == [check]
    assert skipped == []


def test_check_is_skipped_with_a_reason_when_features_are_absent() -> None:
    check = FakeCheck("revision.mrtr", frozenset({Feature.MRTR}))
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == []
    assert skipped[0].check_id == "revision.mrtr"
    assert skipped[0].reason is SkipReason.FEATURE_ABSENT
    assert "mrtr" in skipped[0].detail


def test_active_check_is_skipped_without_a_scope_file() -> None:
    check = FakeCheck("active.ssrf", requires_auth=True)
    runnable, skipped = applicable([check], MODERN, scope=None, target=TARGET, today=TODAY)
    assert runnable == []
    assert skipped[0].reason is SkipReason.NOT_AUTHORISED


def test_active_check_runs_with_a_valid_scope_file() -> None:
    check = FakeCheck("active.ssrf", requires_auth=True)
    runnable, skipped = applicable([check], MODERN, scope=SCOPE, target=TARGET, today=TODAY)
    assert runnable == [check]
    assert skipped == []


def test_model_check_is_skipped_when_no_provider_is_reachable() -> None:
    check = FakeCheck("descriptions.llm_judge", requires_model=True)
    runnable, skipped = applicable(
        [check], MODERN, scope=None, target=TARGET, today=TODAY, models_available=False
    )
    assert runnable == []
    assert skipped[0].reason is SkipReason.MODEL_UNAVAILABLE


def test_no_check_is_ever_silently_dropped() -> None:
    checks = [
        FakeCheck("a"),
        FakeCheck("b", frozenset({Feature.MRTR})),
        FakeCheck("c", requires_auth=True),
    ]
    runnable, skipped = applicable(checks, MODERN, scope=None, target=TARGET, today=TODAY)
    assert len(runnable) + len(skipped) == len(checks)
    assert "2 checks skipped" in summarise_skips(skipped)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/checks/test_registry.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.checks.registry'`

- [ ] **Step 4: Write `base.py`**

```python
# agent_perimeter/checks/base.py
from __future__ import annotations

from typing import Protocol, runtime_checkable

from agent_perimeter._contracts import Severity
from agent_perimeter.model.feature import Feature


@runtime_checkable
class Check(Protocol):
    """Every check declares the features it needs, never a revision string."""

    id: str
    cwe: str
    taxonomy_refs: tuple[str, ...]
    severity: Severity
    requires_auth: bool
    requires_model: bool
    requires_features: frozenset[Feature]

    def run(self, context: object) -> list[object]: ...
```

- [ ] **Step 5: Write `registry.py`**

```python
# agent_perimeter/checks/registry.py
"""Decide which checks apply, and record why the others did not.

A skipped check is never silently absent. The report states the count skipped
and the reason, because a security tool that quietly degrades is worse than one
that was never installed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from agent_perimeter.checks.base import Check
from agent_perimeter.model.feature import FeatureSet
from agent_perimeter.model.scope import AuthorizationRequired, ScopeFile, require_scope


class SkipReason(StrEnum):
    FEATURE_ABSENT = "feature_absent"
    NOT_AUTHORISED = "not_authorised"
    MODEL_UNAVAILABLE = "model_unavailable"


@dataclass(frozen=True)
class Skipped:
    check_id: str
    reason: SkipReason
    detail: str


def applicable(
    checks: Iterable[Check],
    features: FeatureSet,
    *,
    scope: ScopeFile | None,
    target: str,
    today: date,
    models_available: bool = True,
) -> tuple[list[Check], list[Skipped]]:
    runnable: list[Check] = []
    skipped: list[Skipped] = []

    for check in checks:
        missing = check.requires_features - features
        if missing:
            names = ", ".join(sorted(feature.value for feature in missing))
            skipped.append(
                Skipped(check.id, SkipReason.FEATURE_ABSENT, f"target lacks: {names}")
            )
            continue

        if check.requires_model and not models_available:
            skipped.append(
                Skipped(
                    check.id, SkipReason.MODEL_UNAVAILABLE, "no model provider is reachable"
                )
            )
            continue

        if check.requires_auth:
            try:
                require_scope(scope, check_id=check.id, target=target, today=today)
            except AuthorizationRequired as exc:
                skipped.append(Skipped(check.id, SkipReason.NOT_AUTHORISED, str(exc)))
                continue

        runnable.append(check)

    return runnable, skipped


def summarise_skips(skipped: Sequence[Skipped]) -> str:
    """Render the skip summary that the report and the CLI both print."""
    if not skipped:
        return "No checks were skipped."
    by_reason: dict[SkipReason, int] = {}
    for item in skipped:
        by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
    parts = ", ".join(f"{count} {reason.value}" for reason, count in sorted(by_reason.items()))
    return f"{len(skipped)} checks skipped ({parts})."
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/checks/test_registry.py -v --no-cov`
Expected: 6 passed

- [ ] **Step 7: Typecheck and commit**

Run: `uv run mypy --strict agent_perimeter`
Expected: `Success: no issues found`

```bash
git add agent_perimeter/checks tests/checks
git commit -m "feat: add Check protocol and feature-predicate registry with explicit skips"
```

---

### Task 11: `agent-perimeter scan` end to end

**Files:**
- Create: `agent_perimeter/cli.py`
- Create: `docker-compose.yml`
- Create: `.env.example`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `StdioTransport`, `LaunchSpec` (Task 4); `StreamableHttpTransport` (Task 9); `Fingerprint`, `fingerprint` (Task 8); `applicable`, `summarise_skips` (Task 10); `ScopeFile` (Task 3).
- Produces: `app` (Typer application, the `agent-perimeter` console script) with a `scan` command. This is the Week 1 deliverable.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_perimeter._contracts import Claim, Derivation, Method
from agent_perimeter.cli import app
from agent_perimeter.model.feature import Feature, Revision
from agent_perimeter.transport.revision import Fingerprint

runner = CliRunner()

MODERN = Fingerprint(
    revision_claimed=Revision.R2026_07_28,
    features=frozenset({Feature.SERVER_DISCOVER, Feature.RESULT_TYPE}),
    claim=Claim(
        value="2026-07-28",
        method=Method.DETERMINISTIC,
        derivation=Derivation.PROBE,
        observed_at=datetime.now(UTC),
    ),
)


@pytest.fixture
def stub_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_perimeter.cli.fingerprint", lambda transport: MODERN)


def test_scan_reports_revision_and_features(stub_fingerprint: None) -> None:
    result = runner.invoke(app, ["scan", "--target", "https://mcp.example.test/rpc"])
    assert result.exit_code == 0
    assert "2026-07-28" in result.stdout
    assert "server_discover" in result.stdout


def test_active_mode_without_scope_file_refuses() -> None:
    result = runner.invoke(
        app, ["scan", "--target", "https://mcp.example.test/rpc", "--mode", "active"]
    )
    assert result.exit_code == 2
    assert "scope file" in result.stdout


def test_active_mode_with_scope_file_is_accepted(
    tmp_path: Path, stub_fingerprint: None
) -> None:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "target": "https://mcp.example.test/rpc",
                "authorising_party": "Example Ltd",
                "authorised_on": "2026-08-30",
                "attestation": "I authorise active probing.",
            }
        )
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "--target", "https://mcp.example.test/rpc",
            "--mode", "active",
            "--scope-file", str(scope),
        ],
    )
    assert result.exit_code == 0


def test_empty_findings_copy_is_correct(stub_fingerprint: None) -> None:
    result = runner.invoke(app, ["scan", "--target", "https://mcp.example.test/rpc"])
    assert "No findings for the checks that ran" in result.stdout
    assert "You're secure" not in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v --no-cov`
Expected: FAIL with `ModuleNotFoundError: No module named 'agent_perimeter.cli'`

- [ ] **Step 3: Write the implementation**

```python
# agent_perimeter/cli.py
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
from agent_perimeter.model.scope import ScopeFile
from agent_perimeter.transport.base import Transport
from agent_perimeter.transport.revision import Fingerprint, fingerprint
from agent_perimeter.transport.stdio import LaunchSpec, StdioTransport
from agent_perimeter.transport.streamable_http import StreamableHttpTransport

DEFAULT_CONTACT_URL = "https://github.com/USER/agent-perimeter"

app = typer.Typer(add_completion=False, help="MCP security posture scanner.")


def _build_transport(target: str, image: str) -> Transport:
    if target.startswith(("http://", "https://")):
        contact = os.environ.get("AP_CONTACT_URL", DEFAULT_CONTACT_URL)
        return StreamableHttpTransport(target, contact_url=contact)
    return StdioTransport(LaunchSpec(image=image, command=shlex.split(target)))


@app.command()
def scan(
    target: Annotated[str, typer.Option(help="A URL, or a stdio command to launch.")],
    mode: Annotated[str, typer.Option(help="passive or active")] = "passive",
    scope_file: Annotated[
        Path | None, typer.Option(help="Authorisation for active mode.")
    ] = None,
    image: Annotated[
        str, typer.Option(help="Container image for stdio targets.")
    ] = "python:3.12-slim",
) -> None:
    scope = ScopeFile.model_validate_json(scope_file.read_text()) if scope_file else None

    if mode == "active" and scope is None:
        typer.echo(
            "Active mode requires a scope file naming target, authorising_party, "
            "authorised_on and attestation. Pass --scope-file."
        )
        raise typer.Exit(code=2)

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
```

Note: the check list passed to `applicable` is empty in Week 1 — no checks exist yet. Week 2 replaces `[]` with the registered check set. The empty-findings copy is already correct and already tested, so the copy rule cannot regress when checks arrive.

- [ ] **Step 4: Write `docker-compose.yml` and `.env.example`**

```yaml
services:
  app:
    build: .
    environment:
      AP_CONTACT_URL: ${AP_CONTACT_URL}
    depends_on:
      - postgres

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: agent_perimeter
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: agent_perimeter
    ports:
      - "5432:5432"
```

```bash
# .env.example
POSTGRES_PASSWORD=change-me-locally
AP_CONTACT_URL=https://github.com/USER/agent-perimeter
```

No `/var/run/docker.sock` mount, ever. A container holding the Docker socket can start a privileged container mounting `/` — the socket *is* host root — and `app` is the process that parses JSON-RPC from untrusted servers, unbounded schemas and downloaded tarballs. One parser bug with the socket mounted is host root; that is not a trade this scanner makes.

This means `app` cannot launch the containerised stdio launcher itself: the stdio path runs on the **host**, via the `agent-perimeter` CLI (Task 11's `scan` command) on a machine with Docker installed — the CLI is the actual product for stdio targets, not a service behind this compose file. `docker compose up` brings up `app` and `postgres` for the HTTP-target and future UI paths only. A containerised stdio path reachable from `app` is out of scope for v1 — rootless Docker with user-namespace remapping, or a socket proxy constrained to `POST /containers/create` with an enforced policy, is a v1.1 idea, not needed here.

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v --no-cov`
Expected: 4 passed

- [ ] **Step 6: Run the whole suite with coverage**

Run: `uv run pytest`
Expected: all tests pass, coverage at or above 75%.

- [ ] **Step 7: Lint, typecheck, commit**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict agent_perimeter
git add agent_perimeter/cli.py docker-compose.yml .env.example tests/test_cli.py
git commit -m "feat: add agent-perimeter scan CLI reporting revision and features"
```

---

## Week 1 completion gate

All of these must hold before Week 2 starts:

- [ ] `uv run pytest` passes with coverage at or above 75%
- [ ] `uv run mypy --strict agent_perimeter` reports no issues
- [ ] `uv run ruff check .` and `uv run ruff format --check .` are clean
- [ ] `tests/transport/test_containment.py` passes — network unreachable, rootfs read-only, non-root UID, memory bomb killed, hang timed out (**DoD 4 closed**)
- [ ] `tests/model/test_scope.py` and the CLI active-mode tests pass (**DoD 3 closed**)
- [ ] `agent-perimeter scan --target ...` fingerprints the fixture server at both `2025-11-25` and `2026-07-28`
- [ ] CI is green on `main`

**Two research deliverables run in parallel with the code and gate Week 2, per spec §12:**

- [ ] **B12 reading, 8–10 hours.** The NSA/CISA MCP Cybersecurity Information Sheet, the CoSAI MCP security paper, the OWASP MCP Top 10 and the MCP Security Cheat Sheet, end to end. Reproduce two or three published MCP attacks by hand. The ten `checks/revision/` checks in Week 2 are unwriteable without this. **Deliverable: a committed `docs/threat-model.md` writing up the reproduced attacks.** Eight hours with no artifact is unverifiable, which is not a standard this project can hold others to and not itself.
- [ ] **Source-level verification of the competitive claim.** Clone `snyk/agent-scan` (2,971★, Apache-2.0, active), `cisco-ai-defense/mcp-scanner` (1,051★, Apache-2.0, active) and **`highflame-ai/ramparts`** (96★ — `getjavelin/ramparts` is a 301 redirect, confirmed 29 Aug 2026). Grep for `2026-07-28`, `server/discover`, `resultType`, `cacheScope`, `x-mcp-header`, **`-32020`** and **`Mcp-Protocol-Version`**. Record the findings, with commit SHAs and retrieval dates, in `docs/methodology.md`. **If any of the three already implements revision awareness, stop and revisit positioning before Week 2** — the entire (d) differentiator rests on this being true, and the current evidence is documentation-level only.
- [ ] **Request-shape conformance test passes** — `_meta` nested inside `params`; `protocolVersion` and `clientCapabilities` present; `MCP-Protocol-Version` header present and equal to the `_meta` value; `Mcp-Method` equal to `method`; `Mcp-Name` present **iff** the method is `tools/call`, `resources/read` or `prompts/get`, sourced from `params`. Revision §1.3.
- [ ] **Containment suite passes under Docker's default seccomp profile**, and a real Python MCP server runs to completion inside the sandbox. Revision §7.2.
- [ ] **One long-lived container per scan**: a multi-request sequence observes state the server set on an earlier request. Revision §7.1.
- [ ] **No feature is asserted that was not observed** — an integration test runs the real fingerprinter against the fixture at each configuration and asserts the resulting `FeatureSet` exactly. Revision §2.1.
- [ ] **No `/var/run/docker.sock` mount appears in `docker-compose.yml`.** Revision §1.7.

---

## Subsequent plans

Written at the start of each week against the same spec. Listed here so definition-of-done coverage is visible now.

| Plan | Contents | Closes |
|---|---|---|
| **Week 2** — checks, persistence and SARIF | Spec §5 schema and `alembic` migrations, including the `secret_finding.validated CHECK (validated = false)` invariant — deferred to here because Week 1 persists nothing; `checks/revision/` (10), `checks/static/` (5), `checks/descriptions/` (5), `checks/secrets/` (3); `transport/legacy_sse.py`; fixture flaw matrix extension; SARIF 2.1.0 emitter with `logicalLocations` and `partialFingerprints`; GitHub code scanning render verified with a committed screenshot | DoD 1, 2 |
| **Week 3** — graph, probes, evidence | `graph/build.py` and `graph/policy.py`; `checks/active/` (4, scope-gated); `checks/injection/path_proof.py`; `eval/` corpus, scorer and MCPTox adapter wired into CI; screen 6 report view via `report/html.py` | DoD 5, 6 |
| **Week 4** — census, UI, publish | `census/` pipeline (registry API, PyPI/npm artifacts, SDK-pin detection); tier-2 top-200; the five remaining UI screens on `bok-ui`; census report with raw data and analysis script; `docs/security.md` disclosure policy; axe, keyboard and print; clean-machine compose verification | DoD 7, 8, 9, 10 |
