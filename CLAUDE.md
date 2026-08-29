# Agent Perimeter

Security posture scanner for MCP servers and tool-using agents.
Weeks 1–4 · Accent: signal amber `oklch(0.72 0.16 68)` · Licence: Apache-2.0

**Pitch:** *"You wired an agent into your internal systems. I will show you, with a reproduction for each finding, exactly what an attacker can make it do."*

## Source of truth

- `../Starting_Documents/00-SHARED-FOUNDATION.md` — the substrate. Read in full before anything.
- `../Starting_Documents/01-AGENT-PERIMETER.md` — this project's brief. Read in full.

The briefs win over anything summarised here. This file exists so a fresh session cannot violate a hard rule by accident.

## Workflow

superpowers, in order: `brainstorming` → `using-git-worktrees` → `writing-plans` → `subagent-driven-development` → `test-driven-development` → `requesting-code-review` → `verification-before-completion`. TDD is RED-GREEN-REFACTOR, no exceptions.

## Never (each has a test proving it)

1. **No active probe without a scope file.** Scope file is a first-class schema object: target, authorising party, date, attestation. Fails closed. Unauthorised probing is a criminal-liability question, not a style preference.
2. **Public-registry scanning is passive only.** Fetch manifests, clone public repos, analyse static artifacts. Never invoke tools on a remote server you do not own.
3. **Never validate a discovered secret against a live service.** Store fingerprint only — sha256, entropy, prefix, last4, file+line. Raw value never touches the DB, the logs, the SARIF, or a screenshot.
4. **Every stdio server launches inside a locked-down container.** Non-root, read-only rootfs, no network unless the check needs it, tmpfs scratch, seccomp, memory/CPU caps, hard timeout, no host mounts. Build this before any other feature — scanning a stdio server *is* executing an untrusted binary.
5. **Content under analysis never reaches a tool-capable context.** Tool descriptions are attacker-authored. The judge has no tools, no network, constrained-enum output only, analysed content delimited as data.
6. **Every finding cites a CWE and at least one published taxonomy entry** (OWASP LLM Top 10 / OWASP MCP Top 10 / CoSAI / NSA CSI / MITRE ATLAS), inline in the report.
7. **No exploit weaponisation.** Probes prove reachability and stop. Path traversal reads a benign canary and reports the path.
8. **No named third-party server in the public report.** Aggregate statistics only. Secrets found → notify, never publish.

Inherited from `00`: `CLIENT_CONFIDENTIAL` never reaches a free tier (R4). No hardcoded model names (R1). No secrets in the repo including fixtures. $0 recurring cost. Apache/MIT/BSD deps only — flag any AGPL dependency explicitly rather than adopting it silently.

## Determinism budget

Only `checks/descriptions/llm_judge` may call a model, and only as escalation after rules-based detectors flag something ambiguous. `test_degraded_mode_still_produces_findings` must show **≥90%** of finding classes surviving with every provider disabled — higher than the shared floor, because a security tool that silently degrades is worse than none.

## Stack & layout

Python 3.12+, `uv`, `ruff`, `mypy --strict`. FastAPI. Next.js 15 + `bok-ui`. Postgres + alembic. `docker compose up` reproduces everything on a clean machine.

```
agent_perimeter/
  transport/    stdio (containerised launcher), http_sse, streamable_http, version_negotiation
  discover/     enumerate tools/resources/prompts, capability extraction
  model/        ServerProfile, Tool, CapabilityEdge, ScopeFile
  checks/       base.py (Check protocol) + static/ descriptions/ secrets/ active/ injection/
  graph/        capability graph + policy evaluation
  report/       sarif.py, html.py, onepager.py, registry_report.py
  registry/     passive corpus collection
  api/          FastAPI
web/            Next.js 15 + bok-ui
tests/fixtures/servers/   vulnerable-server fleet, one flaw each, plus clean controls
```

Every check declares: stable id, CWE, taxonomy refs, severity, `requires_auth`, `requires_model`. Returns `Finding` carrying a `bok-core` `Claim` per asserted fact, plus evidence artifact and reproduction command.

`description_hash` + `drift_event` land in the **v1** schema even though drift is a v2 surface. Cheap now, expensive to retrofit — drift detection is the subscription.

## Watch for

- **Spec drift.** MCP moved to a stateless architecture in the 2026-07-28 revision and is not fully backward compatible. Explicit version negotiation, per-revision capability matrix, checks declare which revisions they apply to. **Verify the current revision yourself; do not trust the brief's summary.**
- **You are not first.** `mcp-scan` and others exist. Inventory what ships today before writing a line (brief §13 Q1). Differentiate on enterprise *deployment* posture, the data-path injection simulation, or evidence-graded reporting — or re-scope.
- **False positives end credibility faster than gaps.** Every finding needs a reproduction a sceptic can run. Measure precision/recall against the fixture corpus and publish it.
- **The capability graph can be confidently wrong.** Every edge carries its derivation (schema / description / probe) and renders differently by method.
- **SARIF was built for static analysis.** Use `logicalLocations`, `partialFingerprints`, `properties` for taxonomy. Validate against the 2.1.0 schema in CI and confirm it renders in GitHub code scanning before claiming compatibility.
- Registry collection: respect `robots.txt` and rate limits, identify with a contact URL, record fetch failures as part of the sample description.

## Testing bar

Vulnerable-server fixture fleet · adversarial description corpus including descriptions targeting the scanner itself · spec-revision matrix · sandbox escape tests · boundary tests (no raw secret persisted/logged/emitted; active probes refuse without scope) · SARIF golden files · degraded mode ≥90% · Playwright E2E keyboard-only · axe zero serious/critical. Coverage floor 75%.

## Copy rules

Errors state what happened and what to do, no apology. Empty findings reads *"No findings for the checks that ran"* plus the count skipped and why — never *"You're secure!"*

## Definition of done

Brief §12, ten items. The week-4 deliverable is a working scanner **and** a published, rigorously-scoped registry scan report with sample, population, method, collection window, term definitions, raw data and analysis script. The report is the marketing.

## Before planning

Brief §13 has 7 open decisions; `00` §12 has 7 more. None are answered yet. Do not assume them — ask.
