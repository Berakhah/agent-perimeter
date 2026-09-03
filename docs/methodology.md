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
