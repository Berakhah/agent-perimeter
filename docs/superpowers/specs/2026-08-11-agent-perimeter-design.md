# Agent Perimeter — Design

**Status:** approved (brainstorming, 27 August 2026) · **revised 29 August 2026**
**Scope:** weeks 1–4. v1 only.

> **Supersession.** `2026-08-29-agent-perimeter-plan-revision.md` audits this document and all four plans against the primary sources, live, on 29 August 2026. Where it and this document disagree, **the revision wins** — it carries the evidence. Read it before executing any plan.
**Sources of truth:** `../Starting_Documents/00-SHARED-FOUNDATION.md`, `../Starting_Documents/01-AGENT-PERIMETER.md`. Where this document and a brief disagree, the brief wins unless the disagreement is recorded in §1 below as a decision.

---

## 1. Decisions ledger

Every open decision from brief §13 and the cross-cutting subset of `00` §12, resolved.

### From brief §13

| # | Decision | Answer |
|---|---|---|
| 1 | Positioning after competitive inventory | **(d) spec-revision correctness primary, (c) published precision/recall secondary.** (b) injection sim ships as one signature demo. (a) enterprise deployment posture **dropped** — taken by funded competitors. |
| 2 | Hosted scanner vs CLI + local UI | **CLI + local UI only.** Hosted is an explicit v1 non-goal. The only hosted artifact is a static report site on GitHub Pages. |
| 3 | Injection simulation aggressiveness | **Split A/B.** v1 ships claim A (deterministic path-proof, canary + capability graph). Claim B (does *this* agent bite) ships as a documented BYO-agent adapter. |
| 4 | Disclosure embargo | **90 days, aggregate-only always.** No named third-party server, reply or no reply. Secrets bypass the clock entirely: notify owner and platform immediately, never publish, never validate. |
| 5 | Registry scan scope | **Two-tier.** Tier 1: full census of the official registry via its documented API. Tier 2: top ~200 by downloads, full check suite. Two populations, reported separately. |
| 5b | *(added during design)* Census measurement method | **[REVISED 29 Aug 2026] Public artifacts, plus a sampled `server/discover` of the remote stratum.** Tiers 1–2 are artifacts only — PyPI/npm plus the registry API, zero unsolicited traffic. **Tier 3** sends one unauthenticated `server/discover` to each of n = 100 randomly sampled `remote_only` endpoints, under the registry-collection rules (robots.txt, rate limit, contact URL, opt-out list, no retry), because ~70 % of the registry ships no artifact to measure. Anything beyond that single method — `initialize`, `tools/list`, any probe — stays scope-file-gated. Revision §1.5. |
| 6 | Publish own false-positive rate | **Yes — per check class**, on both the local fixture corpus and third-party MCPTox. No single headline scalar. Corpus and analysis script published. |
| 7 | Licence | **Apache-2.0.** |

### Cross-cutting, from `00` §12 — carry to the other three projects

| # | Decision | Answer |
|---|---|---|
| 2 | Unified `bok` CLI vs four independent | **Four independent.** Only `agent-perimeter` ships a real CLI (CI is its distribution channel); the other three use `python -m <module>`. A command registry in `bok-core` would invert the dependency direction — `bok-core` must remain a library the applications depend on, never an orchestrator that imports them. |
| 4 | Supabase vs compose-only Postgres | **Compose-only, no third-party data processor.** `00` §6 already mandates the compose file as source of truth, so this is near-free, and it buys a sentence no competitor can say on a first sales call. Revisit only for `selector-drift`'s scheduler in week 13. |
| 5 | Public from commit one vs at release | **Public at first release**, full commit history preserved. Protects the one scoopable asset and avoids exposing pre-sandbox commits in a security tool. |
| 6 | Apache-2.0 everywhere vs AGPL here | **Apache-2.0 everywhere.** Hosted is now a non-goal, so AGPL protects a product that does not exist; the entire competitive set is Apache-2.0 and enterprise legal blocks AGPL by policy, which is friction aimed squarely at (d) — a differentiator that only pays off if people run it in CI. Sole authorship keeps relicensing in reserve. |
| 3 | Provider inventory | **Not blocking for weeks 1–4.** See §9. |

---

## 2. Verification findings

Both claims in the brief were independently checked rather than accepted. Recorded here because the product's thesis is that claims are checkable.

### 2.1 MCP specification

**Current revision: `2026-07-28`.** Confirmed against the specification site, which builds from `schema/2026-07-28/schema.ts`. Previous revision `2025-11-25`.

Breaking changes:

1. `initialize` / `notifications/initialized` handshake **removed**. Every request self-carries `io.modelcontextprotocol/protocolVersion` and `clientCapabilities` in `_meta`; servers echo `serverInfo`. Mismatch returns `UnsupportedProtocolVersionError`.
2. Protocol-level sessions and `Mcp-Session-Id` **removed** from Streamable HTTP. Cross-call state now uses server-minted handles passed as ordinary tool arguments.
3. `server/discover` **added and mandatory** — advertises supported protocol versions, capabilities and identity.
4. The HTTP GET endpoint and `resources/subscribe`/`unsubscribe` replaced by `subscriptions/listen`.
5. `ping`, `logging/setLevel`, `notifications/roots/list_changed` **removed**.
6. Tasks moved from core into extension `io.modelcontextprotocol/tasks`.
7. **MRTR** (Multi Round-Trip Requests) replaces all server-initiated requests; the server returns `InputRequiredResult`, the client retries carrying `inputResponses`.
8. All results carry a required `resultType`: `complete` or `input_required`.
9. SSE resumability removed (`Last-Event-ID`, event IDs).

Security-relevant minor changes — the basis of the `checks/revision/` family:

- `x-mcp-header`: custom HTTP headers sourced **from tool parameters**. Required `Mcp-Method` / `Mcp-Name` headers make header/body mismatch a downgrade path.
- `CacheableResult`: `ttlMs` and `cacheScope` (`public`/`private`) required on list results. `cacheScope: public` on a sensitive listing is a cache-poisoning primitive.
- `inputSchema`/`outputSchema` loosened to full JSON Schema 2020-12 with `$ref` resolution and composition-keyword bounds.
- OAuth: `application_type` required in DCR; credentials keyed by issuer. **DCR (RFC 7591) deprecated** in favour of Client ID Metadata Documents. **[REVISED]** `iss` is **not** required of servers: the AS **SHOULD** include it and the *client* **MUST** validate a *present* `iss`. A server omitting `iss` is conformant — flagging it is a false positive.
- **[REVISED — added, missed by the original reading]** Error-code allocation policy: `-32020` `HeaderMismatch`, `-32021` `MissingRequiredClientCapability`, `-32022` `UnsupportedProtocolVersion`; `-32002` and `-32042` **MUST NOT** be emitted by this revision. These are free, deterministic revision fingerprints — `-32042` uniquely identifies `2025-11-25`, and `-32001/-32003/-32004` identify a release-candidate build. See revision §2.3.
- **[REVISED — added]** `icons` on `Implementation`/`Tool`/`Prompt`/`Resource`, with normative consumer requirements (scheme allowlist, no cross-origin redirects, no credentials, magic-byte validation, size bounds, SVG treated as executable). A whole unshipped check family. See revision §6.1.
- **[REVISED — added]** `Origin` validation **MUST** and localhost binding **SHOULD** on Streamable HTTP, against DNS rebinding. See revision §6.2.
- **[REVISED — added]** OpenTelemetry `traceparent`/`tracestate`/`baggage` reserved in `_meta`; deterministic `tools/list` ordering **SHOULD**; unsolicited task handles now permitted. See revision §6.3–§6.5.
- **[REVISED — corrected]** `serverInfo` is **SHOULD**, is not verified by the protocol, and implementations **SHOULD NOT** rely on it for security decisions. It is not "echoed" as a requirement.
- **[REVISED — corrected]** `x-mcp-header` is an **annotation inside a parameter's schema** whose value names the header suffix (`Mcp-Param-{Name}`), not a property called `x-mcp-header`. Values are Base64-encoded by conforming clients, so an unconstrained string is *not* a header-injection primitive. See revision §1.8.

Deprecated: Roots, Sampling, Logging; the HTTP+SSE transport; DCR.

Consequences: `http_sse` is a formally deprecated transport and is demoted to legacy-compat; `version_negotiation` is obsolete as conceived, because there is no handshake to negotiate; and the revision introduces security surfaces for which no published check exists.

### 2.2 Competitive inventory

Open-source, shipping today:

| Tool | Owner | Coverage | Licence | Scale |
|---|---|---|---|---|
| `agent-scan` (was `mcp-scan`) | **Snyk** (acquired Invariant Labs, Jun 2025) | Multi-IDE discovery, 15+ risk classes, tool poisoning, rug-pull pinning, MDM monitoring | Apache-2.0 | ~3k stars, requires a Snyk API token |
| `mcp-scanner` | Cisco AI Defense | YARA, LLM, Cisco API, VirusTotal, behavioural, CVE; source analysis across 10 languages | Apache-2.0 | ~1.1k stars |
| Ramparts | **`highflame-ai/ramparts`** (was `getjavelin` — redirect confirmed 29 Aug 2026) | 40 YARA rules, evasion-resistant decoding, LLM semantic, OSV.dev, OWASP tagging | Apache-2.0 | 96 stars, static only |
| MCP-Scanner | Knostic | Shodan-based internet-facing MCP discovery | — | closest to deployment posture |
| mcpscanner / MCPScan / Golf / agent-audit | Pangea, Ant Group, others | Hosted AI-Guard; static taint plus LLM; local IDE config checks | — | smaller |

Commercial: Equixly (already updated for 2026-07-28), Levo, CyCognito, Proofpoint, Obot; gateways from TrueFoundry, MintMCP, Lunar, IBM ContextForge, Lasso.

Academic: MCPTox (AAAI; 45 servers, 353 tools, 20 agents; 72.8% ASR on GPT-o1-mini, under 3% refusal), MCPGuard, MCP-ITP, MCP-DPT, MCP-38, over-privileged capability auditing, PentestMCP, A.I.G, AgentDojo, BIPIA.

**Assessment of the brief's three candidate differentiators:**

- **(a) Enterprise deployment posture — taken.** Levo, CyCognito, Proofpoint and Snyk's MDM mode ship it commercially; Knostic ships it open-source. It also requires endpoint agents and cloud integrations that are unavailable here.
- **(b) Data-path injection simulation — half taken.** MCPTox, AgentDojo, BIPIA and A.I.G already drive agents with injected data; Equixly does it commercially. MCPTox owns the headline finding. Productising it against a customer's own agent remains open, but it is the most expensive item in the brief.
- **(c) Evidence-graded reporting — largely open.** No shipping open-source MCP scanner publishes its own precision/recall or false-positive rate. An independent audit of YARA-based MCP scanning found 6 of 27 detections genuine (~78% FP), and MCPTox is a public scoreboard others already score against.

**(d) Spec-revision correctness — open, and the strongest available position.** `2026-07-28` landed 30 days before this design. Of every scanner inventoried, none mentions any MCP spec revision. They scan configuration files and tool metadata — revision-agnostic by accident, and therefore structurally unable to check what the revision introduced. Equixly is the only party found to have updated, and is commercial.

**Evidence limit, stated and scheduled for closure:** the "no spec-revision awareness" finding is documentation-level across the three largest tools, not source-level. It is the claim the census report rests on, so it is verified in source during week 1, before any publication. If it fails verification, the positioning is revisited before the report is written, not after.

---

## 3. Positioning

Agent Perimeter is **the first MCP scanner that knows which revision of the protocol it is looking at**, and the only one that publishes its own precision and recall.

The buyer sentence is unchanged: *"You wired an agent into your internal systems. I will show you, with a reproduction for each finding, exactly what an attacker can make it do."*

The report's headline claim, which nobody else can currently make: **[REVISED 29 Aug 2026]** *of the N servers in the MCP registry, what fraction show `2026-07-28` support one month after it shipped* — stated as a **two-stratum estimate**: artifact-derived for servers distributed as an npm or PyPI package, and `server/discover`-derived for a random sample of the `remote_only` stratum. Both strata, both methods and both intervals are reported separately and **never pooled into one unqualified number**.

The original wording was **not supportable by an artifact-only method**. Verified 29 August 2026: of a 100-row registry sample, 71 entries carry only `remotes` and 30 carry `packages`, so artifacts characterise roughly 30 % of the population. **Decided 29 August 2026:** rather than narrow the claim to the artifact stratum or enumerate all ~4,000 endpoints, sample the remote stratum — n = 100, one unauthenticated `server/discover` each, seeded and reproducible, under the registry-collection rules with a published opt-out. That bounds the otherwise unmeasured 70 % to roughly ±10 pp for 100 requests instead of 4,000. Revision §1.5 carries the full resolution, the Tier-3 constraints and the revised passive-only guarantee.

(d) has an estimated shelf life of roughly six months. That suits a four-week project; it does not suit a two-year one. (c) is durable and is what remains once the incumbents catch up on the spec, which is why both ship in v1.

---

## 4. Architecture

Six changes to brief §5; everything else stands.

| Brief | Becomes | Why |
|---|---|---|
| `transport/version_negotiation.py` | `transport/revision.py` | No handshake exists to negotiate; it fingerprints |
| — | `transport/features.yaml` | Revision to FeatureSet bundles, as data |
| `transport/http_sse.py` | `transport/legacy_sse.py` | Formally Deprecated in 2026-07-28 |
| — | `checks/revision/` | Differentiator (d) |
| `registry/` | `census/` | Artifact-only collection |
| — | `eval/` | Differentiator (c) |

```
agent_perimeter/
  transport/
    stdio.py             containerised launcher    <- BUILD FIRST (B3)
    streamable_http.py   2026-07-28 primary
    legacy_sse.py        deprecated transport, legacy targets only
    revision.py          fingerprinter
    features.yaml        Revision -> FeatureSet bundles
  discover/   enumerate.py, capability.py
  model/      profile, tool, edge, scope, feature
  checks/
    base.py, registry.py
    static/       auth_mode, tls, token_passthrough, scope_breadth, session_state
    revision/     request_state_binding, param_header_injection, cache_scope,
                  schema_composition, header_body_mismatch, registration_mode,
                  issuer_validation, deprecated_features, state_handle_exposure,
                  conformance_mismatch
    descriptions/ unicode_anomaly, imperative_injection, name_schema_mismatch,
                  shadowing, llm_judge (escalation only)
    secrets/      config_scan, env_scan, history_scan      (fingerprints only)
    active/       path_traversal, ssrf, command_injection, confused_deputy
    injection/    path_proof.py (claim A), agent_adapter.py (claim B)
  graph/      build.py, policy.py
  census/     fetch.py, artifacts.py, detect.py, sample.py
  eval/       corpus.py, score.py, mcptox.py
  report/     sarif.py, html.py, onepager.py, census_report.py
  api/        FastAPI
  cli.py      agent-perimeter scan | census | eval
web/          Next.js 15 + bok-ui
tests/fixtures/servers/   parameterised fixture + config matrix
```

### 4.1 Revision model (approach B — feature predicate)

Checks declare the protocol **features** they require, never a version string:

```python
class Check(Protocol):
    id: str
    cwe: str
    taxonomy_refs: list[TaxonomyRef]
    severity: Severity
    requires_auth: bool
    requires_model: bool
    requires_features: frozenset[Feature]
```

The engine derives applicability from the `FeatureSet` actually observed. A revision is a *named bundle of features* defined in `features.yaml` — data, not code.

Rationale over a version-set matrix: it handles partial implementers correctly, which is the common case one month after a breaking revision; a future revision adds one bundle rather than editing every check; and findings assert observed behaviour ("exposes `x-mcp-header` with no header/body validation") rather than a version claim, which is the evidentiary standard the rest of the product holds itself to.

### 4.2 Fingerprinting

**Live target:**

1. Call `server/discover`. If it answers, the server is at or above 2026-07-28, and supported versions, capabilities and identity are returned directly — the spec mandates the method.
2. If it errors, attempt `initialize`. If that answers, the server is at or below 2025-11-25, with the revision taken from the response.
3. Neither, and `revision_claimed = UNKNOWN`.
4. **Independently observe features.** Does `tools/list` return `ttlMs` and `cacheScope`? Do results carry `resultType`? Is `extensions` advertised? This produces the `FeatureSet`, and checks key off it — never off the claim.

Separating claim from observation yields `conformance_mismatch`, a finding class that requires this separation to exist at all.

**[REVISED] Observe or abstain.** The Week-1 plan violates this section: observing `server/discover` unconditionally *grants* `MRTR`, `PARAM_HEADERS`, `SUBSCRIPTIONS_LISTEN` and `STATELESS_META`, which re-introduces version-implies-feature through the back door and leaves `conformance_mismatch` able to fire on only 2 of 8 features. Binding rules:

- Only `SERVER_DISCOVER`, `RESULT_TYPE`, `CACHEABLE_RESULT` and `EXTENSIONS` are passively observable as specified.
- `PARAM_HEADERS` is observable from the presence of an `x-mcp-header` annotation in any tool schema — derive it from the listing, not the revision.
- `MRTR` and `SUBSCRIPTIONS_LISTEN` are **not** passively observable. Never assert them; dependent checks skip with `FEATURE_ABSENT`.
- `SESSION_HEADER` is an HTTP response-header observation and is meaningless over stdio.
- `STATELESS_META` describes the *client's* request shape, not the server's. **Remove it from `Feature`.**
- Take the **highest** known entry of `protocolVersions`, not the first; record the full advertised set.
- Follow the specification's normative backward-compatibility probe (POST first; on `400` inspect the body for `-32020/-32021/-32022` before falling back to `initialize`; `404` + `-32601` distinguishes modern-unknown-method from legacy).

See revision §2.1–§2.3.

**Census target, tiers 1–2, with no live traffic:** registry API, then package coordinates, then the PyPI/npm artifact, then parse the declared MCP SDK constraint — distinguishing *pin* / *floor* / *unconstrained*, treating unconstrained as `unknown` (revision §1.6) — then static-scan the source for a `server/discover` handler and `_meta` handling. Emits a `FeatureSet` with `derived_from = ARTIFACT` and confidence strictly below a live probe's, calibrated against the n = 30 live-fingerprint agreement rate.

**Census target, tier 3 — the only live traffic in the census:** for a seeded random n = 100 of the `remote_only` stratum, one unauthenticated `server/discover` and nothing else. Emits a `FeatureSet` with `derived_from = LIVE_DISCOVER`, subject to the observe-or-abstain rules above unchanged — an answer grants only what it states. Revision §1.5.

---

## 5. Data model

Brief §6's eight tables stand. Deltas and additions:

```
scan            + revision_claimed, revision_observed, feature_set_json
                  (replaces the single spec_revision_negotiated)
server_profile  + extensions_json
capability_edge   derived_from in (schema|description|probe|artifact)
finding         + feature_requirements_json, calibration_id
secret_finding    validated  CHECK (validated = false)

census_run      id, started_at, finished_at, population_size, fetch_failures,
                tool_version, method_hash
census_record   census_run_id, registry_id, package_coords, sdk_version,
                feature_set_json, fetch_status, collected_at
eval_run        id, corpus_ref, corpus_version, tool_version, run_at
check_score     eval_run_id, check_id, tp, fp, fn, precision, recall, n
```

Three carry specific weight:

- `secret_finding.validated CHECK (validated = false)` makes hard constraint 3 a **database invariant**. Recording a validated secret requires dropping a constraint, which surfaces in a migration diff.
- `census_run.fetch_failures` — B10 warns that throttling silently invalidates a sample. As a column, the report cannot omit it.
- `census_run.method_hash` binds every published result to the exact collection method that produced it, satisfying B9's versioning requirement mechanically.

`description_hash` and `drift_event` remain in the v1 schema per the brief: drift is the v2 subscription, cheap now and expensive to retrofit.

---

## 6. Pipelines

**Scan (live, authorised target)**

```
ScopeFile absent  ->  active checks refuse, fail closed, non-zero exit
transport.connect()    stdio -> containerised: non-root, ro-rootfs, no network,
                       tmpfs scratch, seccomp, mem/cpu caps, hard timeout,
                       no host mounts
revision.fingerprint() -> revision_claimed + FeatureSet observed
discover.enumerate()   -> tools, resources, prompts
checks.applicable(FeatureSet, scope)
  -> Finding(Claim per asserted fact, evidence artifact, reproduction command)
graph.build() -> edges carrying derived_from -> policy.evaluate()
report.{sarif, html, onepager}
```

**Census (artifact-only)**

```
registry API paginate     -> full population, stated exactly
census.artifacts.fetch()  -> PyPI / npm only
census.detect()           -> SDK pin + source scan -> FeatureSet(ARTIFACT)
tier 2: sample.top_n(200 by downloads) -> full suite, source-level
report.census_report      -> aggregate only, methodology footer, raw data + script
```

The census report is generated by `report/html.py` as a **static artifact**, deliberately not by the Next.js application. This breaks the week-4 dependency between the UI and the report: if the UI slips, the report still ships.

**Eval — runs in CI on every commit**

```
eval.corpus (labelled fixtures) + eval.mcptox (third-party benchmark)
  -> full check suite -> predictions
  -> eval.score -> per-check tp/fp/fn/precision/recall/n
  -> docs/methodology.md table + versioned check_score rows
```

Regenerating on every commit is what prevents the published number drifting from reality, and answers the "anchored on a stale figure" objection to publishing at all.

**MCPTox re-use, stated honestly:** MCPTox measures *agent* attack-success-rate. This project re-uses its labelled poisoned metadata as a *scanner detection* corpus. The labels support that use, but it is not the use the paper made of it, and `docs/methodology.md` must say so explicitly.

---

## 7. Failure handling

1. **Refusals are features.** An active check without a valid ScopeFile raises `AuthorizationRequired`, exits non-zero, and names the specific missing attestation field.
2. **Sensitivity violations are hard failures.** `CLIENT_CONFIDENTIAL` toward a free tier raises `SensitivityViolation`. Never a warning.
3. **Partial failure is the common and dangerous case.** An erroring check records `status=errored` with a reason; the scan continues. Output reads "No findings for the checks that ran" plus the skipped count and reason. **A skipped check is never silently absent from the count** — silent degradation is what the 90% rule exists to prevent.
4. **Containment breaches are findings about the target.** A stdio server exceeding limits or attempting egress is killed, a `containment_event` is recorded, and a finding is raised against the server — not swallowed as an operational error.

**Determinism budget:** 29 check classes — 5 static, 10 revision, 5 descriptions, 3 secrets, 4 active, 2 injection. Exactly one (`llm_judge`) is model-dependent. With all providers dark, **28/29 = 96.6%** against the project's 90% floor. The claim-A/claim-B injection split is what preserves this; a bundled model-driven agent would have pushed injection into the model-dependent set.

`conformance_mismatch` defaults to `info` severity and escalates only where a specific gap has a named security consequence. A server mid-migration is not vulnerable, and a noisy check would damage the precision figure the positioning depends on.

---

## 8. Requirements on `bok-core`

Not designed here. These are requirements `00` §4 does not currently cover, to be carried to the `backoffice-kit` session.

1. **`Claim` derivation granularity.** `method: DETERMINISTIC|MODEL|HUMAN|DERIVED` is insufficient — a capability edge derived from `SCHEMA` versus `DESCRIPTION` versus `PROBE` versus `ARTIFACT` is all deterministic with materially different trustworthiness. B9 requires edges to render differently by derivation. Add an optional `derivation` field to `Claim`, or a `Source` subtype carrying the extraction method.
2. **`boundary/fingerprint.py`.** `SecretFingerprint(sha256, entropy, prefix, last4, location)` whose constructor accepts the raw value and structurally guarantees it is never retained, logged, or subsequently reachable. `redact.py` redacts; nothing currently fingerprints. `ledger-sense` needs the identical primitive.
3. **SARIF `logicalLocations` first-class.** Per B7, runtime findings have no natural `physicalLocation`. The emitter must support `logicalLocations`, `partialFingerprints` and `properties`, not only file-and-line.
4. **Constrained decoding and enforced tool-denial in the gateway.** B6 requires the judge to emit a constrained enum with no tools and no network. `gateway/router.py` needs a `response_schema` parameter and a `tools_disabled` mode that is *enforced* rather than requested — otherwise B6's mitigation is a prompt, and a prompt is not a security boundary.
5. **Calibration state on `Claim`.** B10 and `ConfidenceMeter` require "uncalibrated" to be structural: `confidence` needs a companion `calibration` field carrying the reliability basis, so an uncalibrated model score cannot be rendered as a fact.
6. *(soft)* Per-class scoring (`findings/eval.py`). Built locally in `eval/score.py` first; propose promotion when `ground-truth` needs the same thing.

---

## 9. Model providers

Agent Perimeter is the **least model-dependent** of the four projects: only `checks/descriptions/llm_judge` may call a model, escalation-only, and the content analysed is public tool descriptions (`PUBLIC` sensitivity). The provider inventory is therefore **not blocking for weeks 1–4**, though it is blocking for `ledger-sense`.

To check, per provider — Google AI Studio, Groq, Cerebras, OpenRouter (`:free`), Mistral, Cloudflare Workers AI, SambaNova, GitHub Models, NVIDIA NIM. **Exclude the Cohere trial key** (non-commercial only; B3).

| Field | Method |
|---|---|
| `reachable` | A real API call from the machine that will run this — free tiers geofence silently |
| `trains_on_data` | Terms URL **plus retrieval date** |
| `commercial_use` | Permitted on the *free* tier specifically |
| `limits` | RPM / TPM / RPD from the live console for the key-owning project |
| `structured_output` | **Decisive here.** B6 needs a constrained enum. No constrained decoding means unusable for the judge lane at any quota |
| `live_model_ids` | Current free catalogue contents |

These six fields are the schema of `boundary/policy.py`'s capability matrix and `models.yaml`'s lane entries. Record results in `docs/methodology.md`.

---

## 10. UI

Brief §7's six screens, unchanged, plus two deltas:

- The findings table gains a **derivation / feature column** — which observed features made each check applicable.
- A **revision conformance strip** heads the findings screen: *claims 2026-07-28 · observes 7 of 10 features · 3 conformance gaps*. Not a new screen, a header element. It renders differentiator (d) in about four seconds.

The census report and the precision/recall table are static artifacts (GitHub Pages, `docs/methodology.md`), not application screens.

Quality floor per `00` §5.5: WCAG 2.2 AA via axe-core in CI with zero serious or critical violations; full keyboard operation; designed empty, loading, error and partial states; skeletons never spinners; responsive to 375px; `prefers-reduced-motion` respected; a print stylesheet on every report view.

---

## 11. Testing

| Test class | Proves |
|---|---|
| Sandbox escape suite — egress, out-of-container write, unbounded memory | DoD 4 |
| ScopeFile refusal tests | DoD 3 |
| Spec-revision matrix — transport checks against each supported revision fixture | DoD 1 |
| Vulnerable fixture fleet, one flaw per instance, plus clean controls | DoD 6 |
| Adversarial description corpus **including descriptions targeting the scanner** | B6, DoD 6 |
| Boundary — no raw secret persisted, logged or emitted; never validated | Constraint 3 |
| SARIF golden files, 2.1.0 schema validation, and **confirmed rendering in GitHub code scanning** | DoD 1 |
| `test_degraded_mode_still_produces_findings` at or above 90% | Determinism budget |
| Playwright keyboard-only; axe zero serious/critical; print | DoD 9 |
| `docker compose up` on a clean machine | DoD 10 |

Coverage floor 75%. Property tests (`hypothesis`) on anything parsing untrusted input.

**Fixture strategy:** one **parameterised** MCP fixture server driven by environment variables, not ten hand-built servers. Each *instance* exhibits exactly one flaw, satisfying brief §11 literally, while collapsing ten server builds into one plus a config matrix.

B7's SARIF rendering check is a manual verification with a committed screenshot, not a schema assertion — the brief requires confirming that it renders, not assuming it.

---

## 12. Four-week sequence

**Week 1 — foundation and threat model.** Containerised stdio launcher first (B3: scanning a stdio server is executing an untrusted binary). Streamable HTTP transport. Revision fingerprinter and `features.yaml`. ScopeFile schema, failing closed. Check protocol and registry. Parameterised fixture at two revisions. **Plus 8–10 hours of B12 reading** — the NSA CSI, the CoSAI paper, and the OWASP MCP material end to end, and two or three published MCP attacks reproduced by hand; the `checks/revision/` family is unwriteable without it. **Plus source-level verification of the "no spec-revision awareness" competitive claim.**

*Gate: sandbox escape tests pass; a scan produces a FeatureSet against fixtures at two revisions.*

**Week 2 — checks.** `revision/` (10), `static/` (5), `descriptions/` (5, judge escalation-only), `secrets/` (3). Fixture config matrix. SARIF emitter with `logicalLocations` and `partialFingerprints`.

*Gate: SARIF validates against 2.1.0 and is confirmed rendering in GitHub code scanning.*

**Week 3 — graph, probes, evidence.** Capability graph and policy predicates. `active/` (4, scope-gated). `injection/path_proof` (claim A). `eval/` corpus, scorer and MCPTox adapter, wired into CI. **Screen 6, the report view, is built here** as server-rendered HTML via `report/html.py`, ahead of and independent of the Next.js application — this is what decouples publication from the UI.

*Gate: per-check precision/recall generating on every commit; active probes provably refuse without a scope file.*

**Week 4 — census, UI, publish.** Census pipeline. Tier-2 top-200. Web UI: **the five remaining screens** (scan setup, live scan, findings, capability graph, drift stub) on `bok-ui`; screen 6 already exists from week 3. Census report with sample, population, method, collection window, term definitions, raw data and analysis script. `docs/security.md` disclosure policy. axe, keyboard and print. Clean-machine compose verification.

*Gate: all ten DoD items.*

**Risk and descope lever.** Week 4 is the tightest. Two mitigations, in order: the census report is generated by `report/html.py` rather than the Next.js app, so a UI slip does not block publication; and tier-2 `n` scales from 200 down to 50 without weakening any claim, because the two populations are reported separately. Tier 1 — the full census, cheap API pagination — carries the headline finding and is not at risk. If the week slips further, the UI reduces to the report view plus the capability graph, which is what DoD 5 and 9 actually require.

---

## 13. Open risks

- **(d) has a shelf life.** Estimated six months before the incumbents ship revision awareness. (c) is the durable position; both ship in v1 for that reason.
- **The competitive claim is documentation-level.** Closed by source verification in week 1, before publication.
- **Week 4 density.** Mitigated above; watch it from day 18, not day 26.
- **Corpus quality determines the published number.** A bad corpus produces a confidently wrong figure — the exact failure this programme exists to avoid. Corpus construction is week-3 work with clean controls, not an afterthought.
- **B12 is not optional.** Reciting a taxonomy is detectable in a live technical conversation.
