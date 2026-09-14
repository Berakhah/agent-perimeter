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

## Census collection

**Endpoint:** `https://registry.modelcontextprotocol.io/v0/servers`

**Observed:** 2026-09-03, via `curl` with the `agent-perimeter` `User-Agent`
(contact URL included). Confirmed live, not assumed from the plan.

**First published run:** 2026-09-14 — see `docs/census/CHANGELOG.md`
(`## 2026-09-14`) for population, distribution, sample seed, collection
window, method hash, fetch failures and every limitation, and
`docs/census/2026-09-14/` for the report, `records.csv` and
`records.summary.json`. The figures in this section (the ~70% remote-only
estimate, the "4,000+" population) are the 2026-09-03 pre-run observations;
the dated entry carries the measured values (31,953 entries, 56% remote-only).
Tier 2 is a seeded uniform random sample of up to *n* packaged entries per
ecosystem, not a download ranking.

**Pagination.** The response envelope is:

```json
{
  "servers": [ { "server": { ... }, "_meta": { ... } } ],
  "metadata": { "nextCursor": "<name>:<version>", "count": 100 }
}
```

The cursor field is **`nextCursor`** (camelCase), nested under `metadata` -
not `next_cursor`. Reading the wrong name makes `paginate()` believe page 1
is the last page: the loop exits after ~100 servers and logs the run as an
exhausted, complete population, silently truncating a census of 4,000+
servers to roughly 2%. `agent_perimeter/census/fetch.py` reads `nextCursor`
and additionally guards against this specific failure mode: a page 1 that
returns a full page (`limit` entries) with no cursor is treated as a
suspected pagination bug and recorded as a failure, never as a completed
population.

**Envelope nesting.** Each entry in `servers` is not the flat server record.
The actual record is nested one level down under `item["server"]`; the
sibling `item["_meta"]` key carries registry-assigned metadata (publish
status, `isLatest`, timestamps) about the entry, not fields of the server
itself. Reading fields (e.g. `registryType`, `identifier`) directly off the
top-level item instead of off `item["server"]["packages"][*]` silently
produces empty results for every field.

**De-duplication.** Without `?version=latest`, roughly a third of returned
rows are older versions of a server whose latest version also appears
elsewhere in the paged results (confirmed live: the same `name` recurs with
different `version` values). `paginate()` passes `version=latest` and
additionally de-duplicates yielded entries by `name`, keeping the first
occurrence, as defense in depth against the registry ever returning a stale
duplicate despite the filter.

**Packages vs. remotes.** Roughly 70% of registry entries carry a `remotes`
array (`[{"type": "streamable-http", "url": "..."}, ...]`) and no `packages`
field at all - they are remote-hosted servers with no fetchable artifact.
`RegistryEntry.remotes` captures the URLs from that array so those servers
are not invisible to the census. The remaining entries carry a `packages`
array; `registryType` values seen include `npm`, `pypi`, `oci`, `nuget`, and
`mcpb` - `oci`/`nuget`/`mcpb` are recognised as known-but-unmodeled ecosystem
types (Task 1's `Ecosystem` enum models only `pypi`/`npm`) and are counted
distinctly from a genuinely unrecognised or missing `registryType`.

## SDK version floors

`agent_perimeter/census/detect.py`'s `SDK_FLOOR` bounds artifact-derived
feature claims: a package pinned to an SDK release below a feature's floor
cannot be credited with that feature, whatever its source mentions. Every
number the artifact census reports moves if a floor below is wrong.

**Status: verified 2026-09-09**, against the real `python-sdk` and
`typescript-sdk` release history (GitHub releases API + PyPI/npm registry
metadata — not assumed from a plan). `server/discover`, `resultType`,
`CacheableResult` (`ttlMs`/`cacheScope`), and MRTR (`InputRequiredResult`)
are wire-level parts of the same 2026-07-28 protocol revision (per the
[official spec changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)),
not features an SDK adopts one at a time — both SDKs' first `2.0.0` release
is therefore the correct floor for all four, confirmed by both SDKs'
`v2.0.0` release notes explicitly stating they "speak the 2026-07-28
revision."

**npm package rename — a real detection bug, not just a stale number.**
`@modelcontextprotocol/sdk`, the v1 monolithic package, never shipped a 2.x
release: it is frozen at `1.30.0` on the npm registry (checked 2026-09-09).
v2 split the SDK into separately-published packages
(`@modelcontextprotocol/server`, `/client`, `/core`, `/node`, `/hono`,
`/fastify`, `/express`) that "version together" per the
[`@modelcontextprotocol/server@2.0.0` release notes](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0).
A real server implementation depends on `@modelcontextprotocol/server`, not
`@modelcontextprotocol/sdk` — so before this fix, `detect.py` could never
have recognised *any* v2 npm artifact's SDK pin at all, regardless of the
version number in `SDK_FLOOR`. `_JS_SDK_NAMES` now recognises both the v1
and v2 package names, so a v1 pin is still correctly gated below the floor
instead of falling through to "no recognised pin, cannot rule out."

| Feature | Ecosystem | Floor version | Release date | Changelog URL | Date checked |
|---|---|---|---|---|---|
| `server_discover` | pypi (`mcp`) | 2.0.0 | 2026-07-28 | [python-sdk v2.0.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0) | 2026-09-09 |
| `server_discover` | npm (`@modelcontextprotocol/server`) | 2.0.0 | 2026-07-27 | [server@2.0.0](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0) | 2026-09-09 |
| `result_type` | pypi (`mcp`) | 2.0.0 | 2026-07-28 | [python-sdk v2.0.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0) | 2026-09-09 |
| `result_type` | npm (`@modelcontextprotocol/server`) | 2.0.0 | 2026-07-27 | [server@2.0.0](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0) | 2026-09-09 |
| `cacheable_result` | pypi (`mcp`) | 2.0.0 | 2026-07-28 | [python-sdk v2.0.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0) | 2026-09-09 |
| `cacheable_result` | npm (`@modelcontextprotocol/server`) | 2.0.0 | 2026-07-27 | [server@2.0.0](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0) | 2026-09-09 |
| `mrtr` | pypi (`mcp`) | 2.0.0 | 2026-07-28 | [python-sdk v2.0.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0) | 2026-09-09 |
| `mrtr` | npm (`@modelcontextprotocol/server`) | 2.0.0 | 2026-07-27 | [server@2.0.0](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0) | 2026-09-09 |

`param_headers` has no floor row: it is a JSON Schema annotation convention
(`x-mcp-header`) that any source can carry regardless of which SDK version is
pinned, not an API the SDK gates by release - see the comment above
`SDK_FLOOR` in `detect.py`.

## Measured precision and recall

Regenerated on every commit by `agent_perimeter.eval.run`. If this table is
stale, CI is broken.

<!-- EVAL:START -->

Local corpus: `tests/fixtures/corpus.yaml` version 1.0.0, 19 cases.

MCPTox: not run (dataset not present; set AP_MCPTOX_PATH to include it).

| Check | n | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| `descriptions.imperative_injection` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `descriptions.shadowing` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `descriptions.unicode_anomaly` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `injection.path_proof` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `policy.confused_deputy` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.cache_scope` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.conformance_mismatch` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.header_annotation_invalid` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.header_annotation_type` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.header_annotation_unreachable` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |
| `secrets.config_scan` | 19 | 1 | 0 | 0 | 1.00 | 1.00 |

<!-- EVAL:END -->

---

## Competitive claim verification

Per brief `01` §13 Q1 (B8): "inventory what exists, what each covers, and
what each misses… before writing a line." This was not done before Week 1
implementation started — it is recorded now, 2026-09-14, after most of the
build. The gap is a known process failure, not a deliberate skip; it did not
surface a reason to stop, but it did change the claimed differentiators
below.

**Method deviation from the original plan:** most competitors here are
commercial platforms or hosted products, not standalone repos to pin at a
commit SHA — the "Commit SHA / revision-aware?" columns only apply to the
open-source entries. Retrieved via web search, 2026-09-14; sources cited
per row. This is weaker evidence than a direct repo clone + static read (the
census pipeline's own standard), and should be re-verified against primary
sources — vendor docs, the actual repo — before this table is cited in any
published report.

| Tool | Type | What it covers | Repo / commit (if OSS) | Evidence |
|---|---|---|---|---|
| mcp-scan (Invariant Labs) | OSS, now under Snyk (`snyk/agent-scan`) | Static tool-poisoning/rug-pull/cross-origin scan + runtime proxy guardrails, hash-based tool pinning | github.com/snyk/agent-scan (SHA not pinned this pass) | [Invariant blog](https://invariantlabs.ai/blog/introducing-mcp-scan), [snyk/agent-scan](https://github.com/snyk/agent-scan) |
| Cisco mcp-scanner | Commercial | Pre-deploy governance, policy, audit across agentic AI | — | [Cisco vs Snyk vs Pipelock comparison](https://pipelab.org/blog/mcp-scanner-comparison-2026/) |
| Akto | Commercial | Full-lifecycle: agent/MCP discovery, continuous red-teaming, runtime enforcement, agent-to-system interaction mapping | — | [Akto MCP Security](https://www.akto.io/mcp-security) |
| Wiz / Astrix / Endor Labs / GitGuardian | Commercial | Cloud/CNAPP-adjacent MCP visibility, credential/secrets scanning, SCA — adjacent to, not competing with, this project's core thesis | — | [Astrix: State of MCP Server Security 2025](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/) |
| Enkrypt AI | Published report | Registry census: 1,000 servers scanned, 33% with critical vulns | — | [Enkrypt AI](https://www.enkryptai.com/blog/we-scanned-1-000-mcp-servers-33-had-critical-vulnerabilities) |
| Trend Micro | Published report | Registry census: 19,000 servers, AI-powered sweep | — | [Trend Micro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/hunt-them-all-an-ai-powered-vulnerability-sweep-of-19-000-mcp-servers) |
| Independent July-2026 census | Published report | 4 directories crawled, 9,695 unique servers, 5,832 with weaknesses | — | [bex.co](https://bex.co/blog/2026/07/09/mcp-vulnerability-census-server-security-checklist) |
| MCP-BiFlow, MCPGuard, MCPTox, MindGuard | Academic | Bidirectional data-flow analysis, automated vuln detection, tool-poisoning/anomaly detection; MCP-BiFlow reports 93.8% recall on a 32-case benchmark | arXiv preprints | [MCPGuard](https://arxiv.org/pdf/2510.23673), [Unsafe by Flow](https://arxiv.org/pdf/2605.07836) |

**Verdict, and the resulting re-scope decision (2026-09-14):** the brief's
three candidate differentiators (§13 Q1 / B8) do not all survive contact
with reality.

- **(a) Enterprise deployment posture — dropped as a differentiator.** Akto
  and Cisco already cover this, with more runtime/enforcement depth than a
  static+active scanner offers. Continuing to claim this ground would be the
  "fourteenth scanner" the brief warns against.
- **(b) Data-path injection simulation driving a live agent — kept, lead
  differentiator.** Nothing found does this specifically; existing tools do
  static analysis or runtime proxy monitoring, not "instrument a target and
  drive a bundled minimal agent through the injection path to prove
  reachability." `agent_perimeter/checks/injection/agent_adapter.py` is
  this project's implementation of exactly that.
- **(c) Evidence-graded reporting with published precision/recall —
  narrowed, not dropped.** Several parties already publish large-N registry
  census numbers (1,000–19,000 servers). The remaining gap is not "nobody
  publishes numbers," it is that none of those numbers are independently
  reproducible: no fixture corpus, no golden SARIF, no CI regenerating the
  table on every commit and failing the build if it drifts. This project's
  differentiator is **reproducibility/auditability**, not volume — its
  registry census will necessarily be smaller than Trend Micro's 19,000, and
  should not try to compete on N.

## Model provider inventory

Per `00` §12 Q3 and spec §9. Not blocking for weeks 1–4 — this project makes
no model calls until the `llm_judge` escalation lands.

**Decided 2026-09-14 (human-partner answer):** no paid provider account
exists yet — free-tier only. `checks/descriptions/llm_judge` therefore runs
in its degraded/disabled lane by default; the rules-based detectors it would
escalate from must stand on their own until a provider account is
provisioned. This is consistent with R4 ($0 recurring cost) and with
`test_degraded_mode_still_produces_findings`'s ≥90% floor — `llm_judge` is
the *only* checker gated on a model per CLAUDE.md's determinism budget, so
running with it permanently disabled is a valid, tested configuration, not a
degraded fallback of last resort.

| Provider | Reachable | trains_on_data | commercial_use | Limits | structured_output | Live model ids | Terms URL + retrieved |
|---|---|---|---|---|---|---|---|
| _none provisioned — free-tier only, decided 2026-09-14_ | | | | | | | |
