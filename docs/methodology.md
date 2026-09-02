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

## Measured precision and recall

Regenerated on every commit by `agent_perimeter.eval.run`. If this table is
stale, CI is broken.

<!-- EVAL:START -->

Local corpus: `tests/fixtures/corpus.yaml` version 1.0.0, 17 cases.

MCPTox: not run (dataset not present; set AP_MCPTOX_PATH to include it).

| Check | n | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| `descriptions.imperative_injection` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `descriptions.shadowing` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `descriptions.unicode_anomaly` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `injection.path_proof` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `policy.confused_deputy` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `revision.cache_scope` | 17 | 1 | 0 | 0 | 1.00 | 1.00 |
| `revision.conformance_mismatch` | 17 | 1 | 16 | 0 | 0.06 | 1.00 |
| `revision.param_header_injection` | 17 | 0 | 0 | 1 | n/a | 0.00 |
| `secrets.config_scan` | 17 | 0 | 0 | 1 | n/a | 0.00 |

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
