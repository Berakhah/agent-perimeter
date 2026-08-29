# Agent Perimeter — Plan Revision and Audit

**Date:** 29 August 2026
**Scope:** `docs/superpowers/specs/2026-08-11-agent-perimeter-design.md` and the four week plans.
**Method:** every external claim re-verified against the primary source, live, on the date above. Every code path in the plans read in full. Findings below carry the evidence that produced them.

This document supersedes the plans where they disagree. It does not supersede the briefs.

---

## 0. Verification log

Primary sources, fetched 29 August 2026. This is the evidence for §1–§9; nothing below rests on the design document's summary.

| Claim under test | Source | Verdict |
|---|---|---|
| MCP current revision is `2026-07-28`; prior is `2025-11-25` | `modelcontextprotocol.io/specification/latest` builds from `schema/2026-07-28/schema.ts`; changelog is "since `2025-11-25`" | **Confirmed** |
| Handshake removed; sessions removed; `server/discover` mandatory; `subscriptions/listen`; `ping`/`logging/setLevel`/`roots/list_changed` removed; Tasks → extension; MRTR; `resultType`; SSE resumability removed | `/specification/2026-07-28/changelog` major changes 1–9 | **Confirmed, 9/9** |
| `x-mcp-header`, `Mcp-Method`/`Mcp-Name`, `CacheableResult`, JSON Schema 2020-12 loosening, `iss`/RFC 9207, `application_type`, issuer-keyed credentials, DCR deprecated, Roots/Sampling/Logging deprecated, HTTP+SSE Deprecated | changelog minor changes + deprecations | **Confirmed** |
| `iss` validation is *required* of servers | changelog minor 7 | **Overstated.** AS **SHOULD** include `iss`; clients **MUST** validate a *present* `iss`. A server omitting it is conformant. |
| Servers *echo* `serverInfo` | `/basic/index`, per-response protocol fields | **Overstated.** `serverInfo` is **SHOULD**, is **not verified by the protocol**, and implementations **SHOULD NOT** rely on it for security decisions. |
| `mcp-scan` → Snyk | `invariantlabs-ai/mcp-scan` 301 → `snyk/agent-scan`, 2,971★, Apache-2.0, pushed 2026-08-28 | **Confirmed** |
| Cisco `mcp-scanner` ~1.1k stars | `cisco-ai-defense/mcp-scanner`, 1,051★, Apache-2.0, pushed 2026-08-28 | **Confirmed** |
| Ramparts is `getjavelin/ramparts` | 301 → **`highflame-ai/ramparts`**, 96★, Apache-2.0 | **Owner is stale.** Week-1 clone target must change. |
| OWASP MCP Top 10 exists | `owasp.org/www-project-mcp-top-10/`, MCP01:2025–MCP10:2025, Phase 3 beta | **Confirmed** |
| MCPTox: AAAI, 45 servers, 353 tools, 72.8 % on GPT-o1-mini, <3 % refusal | arXiv 2508.14925 / AAAI proceedings | **Confirmed.** 1,312 cases from **3 templates by few-shot generation** — a homogeneity limit the plan does not state. |
| MCPTox dataset obtainable | `github.com/zhiqiangwang4/MCPTox-Benchmark` exists, HTTP 200, pushed 2025-12-03. Re-checked 29 August 2026 via `gh api repos/zhiqiangwang4/MCPTox-Benchmark`: `license: null`, no `LICENSE`/`LICENSE.md`/`COPYING` in the root tree (`README.md`, `analysis.ipynb`, `def_tool`, `pure_tool.json`, `response_all.json` only), and the README contains no licensing language | **Confirmed absent, not conditional.** No licence = not redistributable under `00` §3.2. Resolved — see §10 item 2. |
| Official registry API and pagination | `registry.modelcontextprotocol.io/v0/servers?limit=100` → `{servers, metadata:{nextCursor, count}}` | **Confirmed — and the plan has the field name wrong.** See §1.4 |
| Registry exposes download counts | 100-row sample: no `downloads`, `stars`, `install_count` or popularity field anywhere | **Refuted.** Tier-2 "top 200 by downloads" has no registry data source. |
| Registry population shape | 40 pages × 100 with `version=latest`, still not exhausted → **>4,000 latest servers**. In a 100-row unfiltered sample: 67 unique names, **33 % non-latest rows**, 71 with `remotes`, **30 with `packages`** (29 npm : 1 pypi), 3 % `status: deprecated` | **New, load-bearing.** See §1.4 |
| `?version=latest` filter works | 100/100 rows `isLatest: true` | **Confirmed — and unused by the plan.** |
| GitHub code scanning accepts `logicalLocations` without `physicalLocation` | GitHub SARIF support reference: `result.locations[]` required, `physicalLocation` required, `artifactLocation.uri` + `region.startLine/startColumn/endLine/endColumn` required; **`logicalLocations` is not mentioned in supported properties** | **Refuted.** See §1.1 |
| Code scanning is free on private repos | GitHub docs: "If you want to use code scanning on private repositories, you need a GitHub Code Security license." | **Refuted.** See §1.2 |
| SARIF 2.1.0 schema URL used in Week 2 Task 24 | `raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json` → 200 | **Confirmed** |

**Net:** the positioning survives verification. Differentiator (d) is real — `2026-07-28` is current, and while the incumbents are actively maintained, the "no revision awareness" claim remains documentation-level, so the Week-1 source verification is still necessary. Differentiator (c) is real and open. What does *not* survive is a set of specific implementation decisions built on top of correct facts. Those are §1–§7.

The specification also hands you five security surfaces the design never noticed. Those are §6, and they are the cheapest differentiator work in the project.

---

## 1. Blocking defects

Each makes a stated gate unachievable or ships a scanner that is confidently wrong. Fix before the week it lands.

### 1.1 The SARIF emitter cannot render — and a test enforces the failure

Week 2 Task 24 emits `locations[0].logicalLocations` and **asserts `"physicalLocation" not in result["locations"][0]`**. GitHub requires `physicalLocation` with `artifactLocation.uri` and a four-field `region`, and does not document `logicalLocations` as supported at all.

Consequence: the SARIF validates against the 2.1.0 schema, `upload-sarif` accepts it, and **no alert appears**. Week 2's gate ("confirmed rendering in GitHub code scanning", DoD 1) cannot close, and the Step-7 screenshot cannot be taken.

The plan's own instinct is right — "a schema-valid SARIF that GitHub silently drops is worth nothing" — and then it codifies the drop.

**Revision.** Emit **both**. Every result carries a `physicalLocation` anchored to a real artifact, plus `logicalLocations` for tools that use them:

- **Config-derived findings** (`secrets/*`, anything traced to `.mcp.json` or a client config): anchor to the actual file and line. These are genuine `physicalLocation`s and need no invention.
- **Runtime findings**: write a scan-profile artifact into the workspace — `.agent-perimeter/<server-slug>.mcp-profile.json`, one JSON line per tool/observation — and anchor each result to its line. This is what container and DAST scanners do, it makes the "Reproduce" line clickable, and it is honest: the artifact is a real file this tool produced, containing the exact bytes the finding is about.
- Add `properties["security-severity"]` (numeric) so GitHub ranks the ladder; `level` alone collapses CRITICAL and HIGH into `error`.
- Set `partialFingerprints.primaryLocationLineHash` — GitHub uses only that component. Keep `agentPerimeter/v1` alongside for other consumers.
- Align `$schema` with the document actually validated against.

Replace the test with `test_result_carries_both_a_physical_and_a_logical_location`, and add one asserting the anchored path exists on disk after a scan.

### 1.2 The render check cannot be run under the other three constraints

Week 2 Task 24 Step 7 pushes a branch to a remote and reads the Security tab. Three constraints collide:

- "Repo stays private until first release" (Weeks 1–4 global constraint)
- "$0 recurring cost" (`00` §3.1)
- code scanning on a private repo **requires a paid GitHub Code Security licence**

**Revision.** Create a throwaway **public** repository containing only `basic_scan.sarif.json` and the smoke workflow. Upload, screenshot, commit the screenshot to `docs/evidence/sarif-github-render.png` with the public repo URL and date in `docs/evidence/README.md`, delete the throwaway. Nothing leaks: a golden SARIF about a fixture server is not the roadmap. Add this as an explicit sub-step so the conflict is resolved on paper rather than at 2am in week 2.

### 1.3 The Streamable HTTP transport cannot talk to a conforming server — three independent defects

Week 1 Task 9, `agent_perimeter/transport/streamable_http.py`:

1. **`_meta` is in the wrong place.** The plan puts `_meta` as a sibling of `params`. The specification puts it **inside `params`** (`/basic/index` "General fields → `_meta`", and every worked example in the transport page). A request missing the required `_meta` fields is malformed and the server **MUST** reject it with `-32602` and HTTP `400`.
2. **`MCP-Protocol-Version` header is never sent.** "Every POST request to the MCP endpoint **MUST** include an `MCP-Protocol-Version` header", and its value **MUST** match the `_meta` field or the server **MUST** return `400` + `HeaderMismatch` (`-32020`).
3. **`Mcp-Name` is wrong in both value and applicability.** The plan sends the *client* name on *every* request. The spec sources it from `params.name` or `params.uri` and requires it only for `tools/call`, `resources/read`, `prompts/get`. A mismatched `Mcp-Name` on `tools/list` is precisely the header/body mismatch servers **MUST** reject.

The Week-1 test asserts the broken shape (`seen["_meta"]`, `"mcp-name" in seen`), so TDD locks the defect in.

**Revision.** Rewrite the request builder to the spec's worked example, and add a conformance test asserting: `_meta` nested in `params`; `protocolVersion` and `clientCapabilities` present; `MCP-Protocol-Version` header present and equal to `_meta`'s value; `Mcp-Method` equal to `method`; `Mcp-Name` present **iff** the method is one of the three, and sourced from `params`.

Also: the transport sends `Accept: application/json, text/event-stream` and then calls `response.json()`. A server answering with an SSE stream — which it **MAY** do for any request — crashes it. Parse `text/event-stream` and take the final `data:` event.

### 1.4 The census stops at 100 servers and reports it as a complete population

Week 4 Task 2 reads `body["metadata"]["next_cursor"]`. The live field is **`nextCursor`**. `.get("next_cursor")` returns `None` on page one, the loop records `FetchStatus.OK, "exhausted after 1 pages"`, and `population_is_complete` is `True`.

The result is a published census of 100 of 4,000+ servers **asserting completeness**. This is the exact failure the product exists to reject, in the artifact that is the marketing.

Three further population defects in the same task:

- **No `version=latest`.** 33 % of unfiltered rows are older versions of the same server; 100 rows → 67 unique names. Population inflates by roughly half and per-server features are double-counted. `?version=latest` is supported and verified; use it, and additionally de-duplicate on `name`.
- **`registryType` is not just pypi/npm.** `_coords` silently drops `oci`, `nuget`, `mcpb` and anything else to `None`, merging "ecosystem we do not handle" into the same bucket as "no coordinates". Count them separately; the report's `unknown` definition depends on the distinction.
- **~70 % of the registry has no artifact at all.** In the sample, 71/100 entries carry `remotes` and only 30 carry `packages`. `RegistryEntry` has no field for `remotes`, so those servers are invisible.

**Revision.** Correct the cursor field. Add `version=latest` and name de-duplication. Add a `remotes` field to `RegistryEntry` and a `distribution` column to `census_record` with values `package_npm | package_pypi | package_other | remote_only | none`. Add a loud guard: a `nextCursor` on page one followed by termination is a bug, not an exhausted population.

### 1.5 The headline claim is not supportable on the measured population

Design §3: *"what fraction of the public MCP ecosystem can support `2026-07-28`, one month after it shipped."*

The census is artifact-only by hard constraint. Artifacts exist for ~30 % of the registry. For the other ~70 % — remote servers advertising a URL — there is no artifact to parse, and the design gates live `server/discover` behind a scope file. The honest denominator is "registry entries distributed as an npm or PyPI package", not "the public MCP ecosystem".

Week 4's report machinery already handles this correctly — `unknown` is reported separately and never folded into a denominator. The defect is that **the positioning promises a number the method cannot produce**, and nobody notices until the report is written in the last week.

**Decided 29 August 2026 — neither reading as framed. Sample the remote stratum.**

The choice was posed as census-or-nothing, and it does not have to be. The remote population needs an **estimate**, not an enumeration. A random n = 100 of `remote_only` endpoints, one unauthenticated `server/discover` each, bounds that stratum to roughly ±10 pp at 95 % — enough to state a combined figure with an interval, for 100 requests rather than ~4,000.

**Tier 3, new. What it does, and what constrains it.**

- **Frame.** The `remote_only` stratum of the de-duplicated Tier-1 population. Sample drawn with a seeded RNG; seed and frame snapshot published beside the raw data, so the draw is reproducible without re-issuing a single request.
- **One request per host.** A single `server/discover`. No `initialize`, no `tools/list`, no backward-compatibility fallback, no retry. A non-answer of any kind is recorded as `unreachable` and that host is never contacted again — including on a re-run, which reads the previous run's log.
- **The registry-collection rules in `CLAUDE.md` are what make this passive, so they are load-bearing rather than courtesy:** honour `robots.txt`, rate-limit, identify with a contact URL in `User-Agent`, record every fetch failure as part of the sample description. Add an opt-out list consulted before every request and documented in the report.
- **`derived_from = LIVE_DISCOVER`** — a third value beside `ARTIFACT` and `PROBE`, with its own confidence and its own rendering in the capability graph. It is an observation, not an inference; §2.1's observe-or-abstain rules apply to it unchanged, so a `server/discover` answer grants only what it actually states.
- **`docs/security.md` says what Tier 3 sends, to whom, how often, and how to opt out — published before the first request goes out**, not alongside the report.

**Why not the wide reading.** ~4,000 unsolicited requests buys enumeration precision on a stratum that only needs characterising, and it is the paragraph a hostile reader quotes back. **Why not narrow-only.** It leaves ~70 % of the population as a hole the first reviewer asks about, when the specification's own answer — clients **MAY** call `server/discover` before any other request — costs 100 requests to use.

**The headline therefore becomes** *of the N servers in the MCP registry, X % (±e, n = …) show `2026-07-28` support* — a two-stratum estimate, artifact-derived for the package stratum and discover-derived for a sample of the remote stratum, with both strata, both methods and both intervals reported separately and **never pooled into one unqualified number**.

Change surface: Week 4 Tasks 2 and 6, one new Tier-3 task, the passive-only test's host assertion (below), design §3, design §4's census-target paragraph, and `docs/security.md`.

**The passive-only test has to change shape, and this is the part to get right.** Tier 3 contacts hosts that by definition cannot appear on a literal allowlist, so `test_census_only_talks_to_the_allowed_hosts` cannot stand as written. Confine Tier 3 to one module, `agent_perimeter/census/tier3.py`, and split the guarantee in two:

1. Every census module **except** `tier3.py` keeps the literal host allowlist, unchanged.
2. `tier3.py` is asserted structurally instead: it contains exactly one JSON-RPC method string and that string is `server/discover`; it contains no `https://` host literal at all, because its targets come from the frame; and the transitive import walk of §8 forbids it reaching a transport or an active check, like every other census module.

That is a stronger guarantee than the present one, not a weaker one — today's test would happily pass a module that sent `tools/list` to `pypi.org`.

### 1.6 The SDK-pin inference is unvalidated and may be inverted

Week 4 Task 4 asserts: *"a package pinned to an SDK predating `2026-07-28` cannot serve that revision, regardless of what its source says."* Every number in the census rests on this.

Most packages declare a **range** (`mcp>=1.x`), not a pin, so the installed SDK may be arbitrarily newer and the inference **inverts** — a lower bound says nothing about an upper bound. Where a floor genuinely exists, a new SDK does not imply the handlers are implemented; conversely, an SDK providing `server/discover` automatically means the source scan finds nothing while support is present. And `ARTIFACT_CONFIDENCE` is a hand-chosen number with no reliability basis — `00` B10 calibration debt in the flagship artifact.

**Revision — add one task, the highest-value addition to Week 4.** Ground-truth the inference:

1. Take a random n = 30 from the packages the census *can* fetch.
2. Install each into the Week-1 container and **live-fingerprint it**. This is your own copy of a public package running in your own sandbox — not third-party probing, and fully within constraints.
3. Compare artifact-derived `FeatureSet` to live-observed `FeatureSet`. Publish the agreement rate, the confusion matrix, and the resulting confidence.

Distinguish *pin*, *floor* and *unconstrained* in the data and report the three separately; treat "unconstrained range" as `unknown`, not as evidence.

### 1.7 The Docker socket is mounted into the service that parses attacker-controlled input

Week 1 Task 11 and Week 4 Task 17 mount `/var/run/docker.sock` into the `api`/`app` container. The plan's note defends it: the *scanned* container gets no mounts.

That is not the threat. A container holding the Docker socket can start a privileged container mounting `/` — the socket **is** host root. The scanner is the process that parses JSON-RPC from untrusted servers, unbounded schemas, and downloaded tarballs. One parser bug is host root, which defeats B3 entirely. And it ships in a *security tool's* published `docker-compose.yml`, the first file a reviewer opens.

**Revision.** Remove the socket mount. The stdio launcher runs on the host, where the CLI is the actual product; `docker compose up` brings up `db`, `api`, `web` and `fixture` for the UI and HTTP-target paths, and `POST /api/scans` with a stdio target returns a clear refusal explaining that stdio scanning requires the CLI on a host with Docker. A containerised stdio path later means rootless Docker with user-namespace remapping, or a socket proxy constrained to `POST /containers/create` with an enforced policy — both v1.1, neither needed to close DoD 10.

### 1.8 `revision/param_header_injection` detects a field that does not exist

Week 2 Task 6 looks for a **property named** `x-mcp-header` in `inputSchema.properties`, flagged when it is an unconstrained string.

The specification's mechanism is different in shape and in risk:

```json
"region": { "type": "string", "description": "...", "x-mcp-header": "Region" }
```

`x-mcp-header` is an **annotation inside a parameter's own schema** whose *value* is the header-name suffix, producing `Mcp-Param-Region`. The plan's check will never match a real server, and the Week-1 fixture (`AP_FIXTURE_FLAW=param_header`, which adds `properties["x-mcp-header"]`) encodes the same misreading — so the test passes against a fiction.

The premise is wrong too. Clients **MUST** Base64-encode any value that is not safe plain ASCII, so CR/LF cannot reach a header from a *value*; servers **MUST** reject invalid characters. An unconstrained string parameter is therefore **not** a header-injection primitive for a conforming client, and firing HIGH/CWE-113 on every one would be a mass false positive in the differentiator family.

**Revision.** Replace with four checks driven by the spec's own MUSTs — all deterministic, all currently unshipped by anyone:

| Check | What it detects | Basis |
|---|---|---|
| `revision.header_annotation_invalid` | `x-mcp-header` value empty, not an RFC 9110 token, containing CR/LF or control characters, or not case-insensitively unique within the `inputSchema` | Client **MUST** reject and exclude the tool from `tools/list` |
| `revision.header_annotation_unreachable` | annotation on a property not *statically reachable* by a pure chain of `properties` keys — behind `items`, `oneOf`/`anyOf`/`allOf`/`not`, `if`/`then`/`else`, or `$ref` | Spec: makes the tool definition **invalid**; also the natural evasion pattern, honoured by a lax client and invisible to an intermediary |
| `revision.header_annotation_type` | annotated parameter typed `number`, or an integer outside the JS safe range | Spec: `number` explicitly **not permitted** |
| `revision.header_body_mismatch` | server does not validate header against body (already planned, already scope-gated) | Spec: server **MUST** return `400` + `-32020`; the named threat is "a load balancer routing on the header while the server executes the body" |

The first three are passive, high-precision and spec-normative. Strictly better than what the plan has, for the same effort.

Update the fixture flaw matrix: `param_header_bad_token`, `param_header_crlf`, `param_header_behind_oneof`, `param_header_number`, plus a clean control with a valid annotation.

---

## 2. Correctness defects

### 2.1 The fingerprinter invents four of the eight features it reports

`transport/revision.py` (Week 1 Task 8):

- Observing `server/discover` unconditionally adds `MRTR`, `PARAM_HEADERS`, `SUBSCRIPTIONS_LISTEN` and `STATELESS_META`.
- `initialize` succeeding adds `SESSION_HEADER`, which is a Streamable-HTTP transport property and meaningless over stdio.

Only `RESULT_TYPE` and `CACHEABLE_RESULT` are genuinely observed, yet the whole `Fingerprint` carries one `Claim` with `Derivation.PROBE`. This is the design's central promise — "checks key off the observed FeatureSet, never off the claim" — inverted inside the foundation, and it is B9's "confidently wrong" in the module the differentiator depends on.

The knock-on is worse: `conformance_mismatch` computes `BUNDLES[claimed] − observed`, and five of eight features are auto-granted, so **the flagship check can only ever fire on two features**. Its unit tests pass only because they hand-build a `Fingerprint` the real fingerprinter cannot produce. Nothing in Weeks 1–3 tests the fingerprinter→check path.

**Revision.** Observe or abstain:

- `RESULT_TYPE`, `CACHEABLE_RESULT` — from `tools/list`, as now.
- `EXTENSIONS` — from `capabilities.extensions`, as now.
- `SERVER_DISCOVER` — from the call succeeding, as now.
- `MRTR` — not passively observable. Do not add it. Dependent checks skip with `FEATURE_ABSENT`, which is the honest outcome.
- `PARAM_HEADERS` — observable: does any tool schema carry an `x-mcp-header` annotation? Derive from the tool listing, not the revision.
- `SUBSCRIPTIONS_LISTEN` — not passively observable without opening a stream. Drop or gate.
- `SESSION_HEADER` — observable on HTTP only, from a response header. Never over stdio.
- `STATELESS_META` — a property of the *client's* request shape, not the server's. Remove it from `Feature` entirely; three checks use it as a proxy for "modern", which is exactly the version-implies-feature reasoning approach B was chosen to avoid.

Add an integration test: run the real fingerprinter against the fixture at both revisions and at each injected conformance gap, and assert the resulting `FeatureSet` and the `conformance_mismatch` findings. Without it the differentiator is untested end to end.

### 2.2 Revision selection and unknown-revision handling

- `_claimed_revision` returns the **first** parseable entry of `protocolVersions`. A server advertising `["2025-11-25", "2026-07-28"]` is recorded as the older one. Take the highest known, and record the full advertised set on the scan.
- `Revision` is a closed two-value enum. A server claiming `2025-06-18` or `2025-03-26` — both widely deployed — yields `revision_claimed = None` **with the caveat "Server answered neither `server/discover` nor `initialize`"**, which is false: it answered `initialize`. A wrong caveat on a `Claim` in a provenance product is a category error. Add the known revision list, and give unparseable claims a distinct caveat naming the string received.
- The specification defines the backward-compatibility probe precisely: POST a modern request; on `400`, inspect the body — a recognised modern JSON-RPC error (`-32020`, `-32021`, `-32022`) means a modern server, so retry rather than fall back; only an unrecognised body falls back to `initialize`. `404` + `-32601` distinguishes a modern server lacking the method from a legacy `404`. GET/DELETE → `405` on modern servers. Follow it — it is normative, more accurate than "try `server/discover`, then `initialize`", and free.

### 2.3 Error codes are a free, deterministic revision fingerprint the design ignores

The revision allocates `-32020` `HeaderMismatch`, `-32021` `MissingRequiredClientCapability`, `-32022` `UnsupportedProtocolVersion`, and states implementations of this revision **MUST NOT** emit `-32002` (resource-not-found, now `-32602`) or `-32042` (URL elicitation, `2025-11-25` only).

That is four high-signal deterministic observations, including `-32042` as a **unique fingerprint for `2025-11-25`**, and `-32001`/`-32003`/`-32004` as a fingerprint for a server built against the release candidate rather than the final revision — a distinction no other scanner can make. Add `revision.error_code_conformance`.

### 2.4 A raising check aborts the entire scan

Design §7.3 requires an erroring check to record `status=errored` with a reason while the scan continues. **No such handling exists.** `cli.py` runs `for check in runnable: findings.extend(check.run(context))` with no `try`. Active probes are specified to *raise* `AuthorizationRequired`. Checks parse attacker-controlled JSON and can raise `RecursionError`, `UnicodeDecodeError`, `re.error`, `MemoryError`.

**Revision.** Wrap each `check.run` in a `try`, record `CheckOutcome(check_id, status, reason)`, and surface errored checks in the same summary line as skipped ones. Test: a check that raises does not prevent the others from reporting.

### 2.5 Five channels are read but never written

`llm_judge` reads `raw["_ambiguous_tools"]`; `config_scan` reads `raw["_config"]`; `env_scan` reads `raw["_env"]`; `request_state_binding` needs an `input_required` result passive mode never produces; `agent_adapter` needs `raw["_agent_transcript"]`. Only `_repo_path` is wired (via `--repo`).

So of the 29 registered checks, roughly **20 can fire in a default scan**: 5 are auth-gated and skipped without a scope file, and 4–5 more read channels nothing populates. The plans state "23 checks" and "29 checks" without qualification.

**Revision.** Wire the channels or stop counting the checks:

- `_config` / `_env`: add `--config <path>` and `--env-file <path>`, and populate `_env` from the stdio `LaunchSpec.env` for stdio targets. Two lines each — and `secrets/*` is the one class with published prevalence behind it, so leaving it unreachable is the worst trade in the plan.
- `_ambiguous_tools`: define ambiguity concretely. Cheapest honest rule: a description matching a *weak* deterministic signal (one `model_directive` or `exfiltration` pattern, or a `mixed_script` hit) but not a strong one. Emit the ambiguous set from the deterministic checks and read it from a typed field on `ScanContext`, **not** from `raw`, which is documented as unparsed server responses.
- `request_state_binding` / `agent_adapter`: keep, mark them `opportunistic` in the registry, exclude from the headline check count.

### 2.6 Redundant round trips, and a data-consistency hole

A minimal scan calls `server/discover` and `tools/list` inside `fingerprint()`, then again in `cli.scan`, then `tools/list` a third time inside `enumerate_tools()`. Five round trips for two pieces of data — and with the Week-1 stdio transport, **five container launches** (§7.1).

Worse, a server may return a different `tools/list` on each call. `context.raw["tools/list"]` and `context.tools` can then disagree, and checks reading each contradict one another with no way to notice — a silent correctness hole in a scanner whose v2 product is detecting exactly that kind of change.

**Revision.** Fetch once into a `RawResponses` object and derive `tools` from the same bytes. If a second call is ever made deliberately, record it as a distinct observation with its own timestamp — an in-scan `tools/list` divergence is a *finding*, not an inconsistency to paper over.

### 2.7 Smaller correctness items

- `Claim` is `frozen=True` with a `list[Claim]` field: hashing raises at runtime despite the frozen contract.
- `_contracts.py` has no `calibration` field, though design §8 requires it and `finding.calibration_id` is in the schema.
- The `00` §4.1 rule "a `MODEL` claim with `confidence is None` cannot be rendered as a fact" is neither implemented nor tested.
- `SecretFingerprint` uses `__slots__`; `test_fingerprint_object_does_not_retain_the_value` reads `fp.__dict__`, which raises `AttributeError`. The test fails as written.
- `alembic.ini` with `sqlalchemy.url = postgresql+psycopg://…:${POSTGRES_PASSWORD}@…` — `configparser` does not expand `${…}`, and a credential-shaped string in a committed file invites a `gitleaks` hit. Read the URL from the environment in `env.py`.
- `sorted(findings, key=lambda f: f.severity)` sorts a `StrEnum` **alphabetically**: critical, high, info, low, medium. Give `Severity` an explicit rank.
- `ScanContext.reproduction()` interpolates the target into a shell string unquoted. Use `shlex.quote`; the string is copy-pasted out of SARIF and HTML.
- `Check.cwe` and the CWE on emitted findings diverge (`schema_composition` declares `CWE-674`, emits `CWE-918`). CWEs are validated only by a `CWE-\d+` regex — for a product selling citation integrity, an unresolvable CWE is the same defect as an unresolvable taxonomy ref. Register the CWEs you cite, with titles and URLs, and gate them like the taxonomy.
- `ScopeFile` permits no `expires_on` (unbounded authorisation), never checks `authorised_on <= today`, never checks `expires_on >= authorised_on`, and matches `target` by exact string equality — so a trailing slash refuses. Fail closed: require an expiry, cap the window (90 days), normalise URL targets before comparison.
- `taxonomy.yaml` is seeded with `mcp-spec:*` entries, but DoD 2 requires *"a CWE and at least one published taxonomy entry (OWASP LLM Top 10 / OWASP MCP Top 10 / CoSAI / NSA CSI / MITRE ATLAS)"*. `mcp-spec` is not on that list. As written, a `revision/` check citing only `mcp-spec` passes the citation gate and fails DoD 2. Add a `scheme in APPROVED_SCHEMES` requirement — and budget for it, because it bites hardest on the ten revision checks. Most map to `owasp-mcp:MCP07` (auth), `MCP01` (secrets), `MCP10` (context), `owasp-llm:LLM01/LLM02/LLM06`, and MITRE ATLAS.
- Add a CI job that HEAD-checks every taxonomy and CWE URL, allowed to fail soft and open an issue (the `00` §7 nightly-smoke pattern). A citation nobody can follow is the failure this product is named for, and the check is nearly free.

---

## 3. False-positive register — the risk to differentiator (c)

The positioning is *"the only scanner that publishes its own precision and recall."* Below are the checks that will produce false positives on real servers, ranked by damage. Every one is at HIGH or CRITICAL, and none carries a confidence value.

| Check | Severity | Failure mode | Fix |
|---|---|---|---|
| `descriptions.unicode_anomaly` (mixed_script) | **CRITICAL** | `_script_of` splits the Unicode name and treats anything non-`LATIN` as an anomaly. **Any description in Chinese, Japanese, Greek, Arabic, Hebrew, Cyrillic or Devanagari with an English tool name fires CRITICAL.** On a global registry this alone could dominate the published FP rate. | Scope confusable detection to **tool names** (identifiers), use UTS #39 confusable skeletons rather than script-mixing, and drop mixed-script in free text to `info` or remove it. Bidi, zero-width and tag characters stay CRITICAL — those are sound. |
| `descriptions.shadowing` (cross-reference) | **CRITICAL** | Fires whenever any description mentions any other tool's name. Good documentation does this constantly ("use `list_files` first"). Single-word tool names (`get`, `read`) match inside ordinary prose. | Require an *imperative* toward the other tool ("before calling X, you must…", "instead of X"), not a mention. Drop to MEDIUM. Compile patterns once — §7.4. |
| `descriptions.imperative_injection` | **CRITICAL** | Two of eight patterns are ordinary prose: `\byou\s+(must\|should\|will)\b` ("You must provide a valid path") and the exfiltration pattern (`Uploads a file to https://…` is an upload tool's actual purpose). | Delete the bare `you must/should` pattern, or require co-occurrence with a concealment or override signal. Require the exfiltration URL to differ from the server's own origin. |
| `static.token_passthrough` | **HIGH** | Regex includes `secret`, `password`, `credential`. Every secrets-manager MCP server (Vault, 1Password, AWS Secrets Manager) has a `secret` parameter **by design**. | Derive from the capability graph instead of a name regex: fire only when the tool also holds a `net_out` edge — that is the confused-deputy precondition the check claims to detect. MEDIUM without it. |
| `descriptions.name_schema_mismatch` | **HIGH** | `run`, `execute`, `send`, `write` appearing anywhere in a `get_*`/`read_*` description. "Runs asynchronously", "writes the result to stdout". | Require the verb to take the tool's own object, or require a corroborating capability edge. |
| `revision.state_handle_exposure` | MEDIUM | Regex matches `cursor_id` (the **standard MCP pagination cursor**) and `task_id` (the **standard Tasks-extension handle**). `maxLength` is treated as proof of opacity. | Exclude `cursor` and the Tasks handles by name. Drop `maxLength` from the opacity markers. |
| `revision.cache_scope` | MEDIUM | Fires on any `cacheScope: "public"`. For an unauthenticated public server — the majority of the registry — `public` is **correct**. The docstring says "on an authenticated server"; the code never checks. | Require evidence of authentication (a `401` + `WWW-Authenticate` on an unauthenticated request, or resolved AS metadata). Otherwise `info`. |
| `static.auth_mode` | **HIGH** | Fires when `raw["oauth/metadata"]` is empty, and **cannot distinguish "not fetched" from "fetched and absent"**. Its evidence string is a hardcoded sentence asserting a fetch result it never verified. A server using a static bearer key or mTLS has no OAuth metadata and may be perfectly authenticated. | Probe for `401` + `WWW-Authenticate` — the spec's own discovery path — and record the actual observation as evidence. Distinguish `unauthenticated` / `non-oauth` / `oauth` / `not determined`. Never emit fabricated evidence text. |
| `static.scope_breadth` (annotation) | MEDIUM | `readOnlyHint` plus a name starting `run`/`set`/`send`/`post`. `run_query`, `post_process`, `set_filter`. | Require a corroborating write/exec capability edge. |
| `revision.deprecated_features` | LOW | Reads server `capabilities` for `roots` and `sampling` — those are **client** capabilities. Recall ≈ 0 for two of three. | Read the correct side. Drive the list from the published [deprecated features registry](https://modelcontextprotocol.io/specification/2026-07-28/deprecated) rather than a hand-maintained dict. Put the twelve-month deprecation window in the finding text so LOW is self-evidently right. |
| `revision.request_state_binding` | **HIGH** | Asserts "carries no integrity protection" from the fact that a value base64-decodes to JSON. The server may HMAC and store server-side. `count(".") >= 2` is treated as "signed". Nothing in the spec requires `requestState` to be signed. | Reframe as an observation — "`requestState` is transparent: structure is readable" — at MEDIUM. An unverifiable security verdict is exactly the standard this product holds others to. |
| `static.tls` | **HIGH** | Only fires when the target *string* starts with `http://` — i.e. only when the user typed it. Detects nothing about actual TLS: no redirect-to-http, no weak versions, no expired or self-signed certificate, no HSTS. | Either implement a real TLS posture check against the resolved endpoint, or rename it `static.cleartext_target` and stop counting it as TLS coverage. |

**Systemic, and more important than any single row:** eight of these checks record `Derivation.SCHEMA` for what is a **regex over an identifier**. A name match is not a schema fact. The derivation ladder is the product's signature — using its strongest non-probe tier for its weakest evidence undermines the thing being sold.

**Revision.** Add `Derivation.NAME` between `SCHEMA` and `DESCRIPTION`. Reserve `SCHEMA` for structural evidence (`format: uri`, `enum`, `pattern`, declared types, MCP annotations, the `x-mcp-header` annotation). Give every heuristic check a `confidence < 1.0` and let `ConfidenceMeter` render it greyed until calibrated, per `00` B10. One enum value, applied consistently, and the graph becomes defensible.

---

## 4. The evaluation harness cannot falsify the claim it publishes

The deepest problem in the plan set, because it is the differentiator measuring itself.

### 4.1 The scorer is structurally unable to record most false positives

`eval/score.py` counts a check only on cases that explicitly name it in `expect_findings` or `expect_clean`. A check firing on a case where it is not listed is **neither TP, FP nor FN — it is invisible**. `descriptions.shadowing` firing on the `cache_scope_public` case is simply not counted.

**Revision.** Closed-world labelling: every check defaults to `expect_clean` on every case unless the case lists it in `expect_findings`. Standard for detection benchmarks, a five-line change, and it makes the published precision mean what readers will assume it means.

### 4.2 The corpus cannot produce a false positive

Seventeen cases, all generated by one fixture server, with flaws injected to match detectors written by the same author in the same week, and labels authored alongside the checks. Precision and recall will come out at or near 1.00.

**Publishing "precision 1.00" measured on 17 self-authored cases is worse than publishing nothing.** The target buyer is a sceptic; that number invites exactly the dismantling the report is meant to survive. And none of the §3 false-positive modes can appear in this corpus — it contains no multilingual server, no well-documented multi-tool server, no secrets-manager server.

**Revision — the single highest-leverage change in this document.** Week 4 already collects thousands of real registry servers' tool metadata. Add:

1. **A real-world precision sample.** Random n = 100 from the census population, run the full deterministic suite over their tool metadata, and **manually adjudicate every firing** as TP or FP. That yields precision on a real population with a stated sample, method and adjudication rule.
2. **Keep recall on the fixture corpus and MCPTox** — recall needs known positives.
3. **Report the two from different populations, clearly labelled**, with the adjudication log published alongside.

Roughly a day, reuses data already being collected, and converts (c) from a self-graded exam into the most defensible artifact in the category. It is also the only way the §3 modes get discovered before a customer finds them.

### 4.3 The harness does not exercise the thing it measures

`eval/harness.run_case` builds `Fingerprint(features=BUNDLES[revision])` — the **full bundle**, rather than fingerprinting. So `conformance_mismatch` computes `BUNDLES[rev] − BUNDLES[rev] = ∅` and can never fire, while the corpus contains `missing_result_type → expect_findings: [revision.conformance_mismatch]`. That case is a guaranteed false negative, the differentiator's recall is measured at zero, or someone quietly edits the label.

**Revision.** Call the real `fingerprint(transport)`. The eval harness must run the same path a scan runs, or it is measuring something else.

### 4.4 Further eval defects

- **`run_case` runs with `scope=None`**, so all four active probes and `injection.path_proof` are skipped. Five of 29 checks are never measured and publish as `n/a`. Provide a fixture-scoped `ScopeFile` — authorising probing of your own fixture is exactly what a scope file is for.
- **The MCPTox labelling is wrong.** `POISON_CHECKS = (imperative_injection, unicode_anomaly)` marks every poisoned sample as expected to fire **both**. A sample with an imperative but no Unicode trick counts as a false negative for `unicode_anomaly`, across ~1,312 cases. Label as "≥1 of the poisoning checks fires".
- **The MCPTox adapter's input format is invented.** `{id, tool_name, description, poisoned}` is a guess. Confirm against the repository before Week 3, and gate on the licence — an unlicensed dataset cannot be vendored or redistributed under `00` §3.2. The "operator supplies a path, else record `MCPTox: not run`" design already handles the fallback correctly.
- **State MCPTox's homogeneity.** 1,312 cases from **3 templates by few-shot generation**. A detector tuned on it will report inflated recall. This belongs in the same paragraph as the re-use note, which is otherwise exemplary.
- **`policy.confused_deputy` is not a registered check.** Week 3 appends `evaluate(edges, context)` findings *after* `applicable()`, so policy findings bypass the registry: no skip accounting, no auth gate, no citation gate, not in `ALL_CHECKS`, not counted in the 29. The corpus expects it by id. Register policy predicates as checks.
- **10 of 17 corpus cases reference fixture flaws that do not exist** (`param_header_enum`, `unicode_bidi`, `imperative_injection`, `verbose_description`, `shadowing`, `config_secret`, `config_placeholder`, `deputy_tools`). Week 2's "fixture flaw matrix extension" is mentioned but never specified as a task. Add it, with the full matrix enumerated.
- **`run.py` imports `eval.harness` which is written two steps later**, so `test_run.py` fails at import when the plan is followed in order.
- **`write_methodology_table`** silently produces garbage when the markers are absent. Fail loudly.

### 4.5 The degraded-mode number is measured in a way that cannot fail

`test_degraded_mode_still_produces_findings` computes `len([c for c in ALL_CHECKS if not c.requires_model]) / len(ALL_CHECKS)` = 28/29 = 96.6 %.

That counts **registrations**, not findings. The brief says *"≥90 % of finding classes surviving with all providers disabled"* — classes that still *produce* findings. Given §2.5, the honest number against a real target is materially lower.

**Revision.** Measure it: run the full suite against the fixture corpus with providers disabled and count distinct `check_id`s that emitted at least one finding, over the count with providers enabled. That is the claim the brief makes, it can fail, and a metric that cannot fail is not a metric — in a product whose thesis is metric integrity, this one matters more than most.

---

## 5. The scanner's own hardening

The scanner parses attacker-authored JSON, attacker-authored schemas and attacker-authored tarballs. Week 1 correctly containerises the *server*. Nothing protects the *scanner*.

### 5.1 The `$ref` walker is a denial-of-service vector against the check that detects denial of service

`schema_composition._collect_refs` recurses over attacker-controlled JSON with no depth bound. A ~1,000-deep nested schema raises `RecursionError`, which is not a `TransportError`, and per §2.4 there is no handler — so **a malicious server kills the scan using the check written to detect malicious schemas**.

The specification anticipates this exactly: *"Implementations **SHOULD** apply reasonable bounds, such as a maximum schema depth, a cap on the total number of subschemas, or a per-validation time budget, to prevent a malicious schema from acting as a Denial-of-Service vector against the validator."*

**Revision.** Add ingest limits at the parsing boundary and apply them everywhere: max response bytes, max tool count, max description length, max schema depth, max subschema count, max total nodes. Exceeding a bound is itself a **finding about the target**, in the spirit of design §7.4's containment events. Rewrite `_collect_refs` iteratively with an explicit stack.

### 5.2 The scanner must never dereference a `$ref`

The specification is emphatic: *"Implementations **MUST NOT** automatically dereference `$ref` values that resolve to a network URI."* Opt-in only, host allowlist, reject loopback/link-local/private, timeouts, size limits, log dereferenced URIs.

Nothing in the plan dereferences today — but nothing forbids it either, and a future contributor adding `jsonschema` validation with remote resolution turns the scanner into an SSRF proxy pointed at whatever the target names. **Add a test** in the spirit of `test_passive_only.py`: no module under `agent_perimeter/checks` may construct a resolver with remote fetching enabled.

Strengthen `_is_external` while you are there: it is case-sensitive (`HTTPS://EVIL` evades) and misses `file:`, `ftp:`, `ws:`. A `$ref` to a cloud metadata address (`169.254.169.254`, `metadata.google.internal`) deserves CRITICAL, not the same HIGH as any external reference.

### 5.3 `_is_recursive` catches only direct self-reference

`A → B → A` is missed, and JSON-Pointer escaping (`~0`, `~1`) is not handled, so evasion is trivial. Replace pattern-matching for recursion with the bound-checking from §5.1 — measure depth and subschema count against a limit. That is what the spec asks for, it is simpler, and restructuring cannot evade it.

### 5.4 `git log -p --all` on an untrusted repository, unbounded, on the host

`secrets/history_scan` runs `git log -p --all` with `capture_output=True` over a repository the census cloned from an untrusted third party. Output buffers entirely in memory — **guaranteed OOM on a large repository**, and `timeout=120` does not bound memory.

More seriously, the Week-4 census clones untrusted repositories on the host. `git clone` of a hostile repository is a code-execution surface (templates, hooks, submodule configuration). B3's reasoning — "launching a stdio server is arbitrary code execution on your machine" — applies with equal force to cloning and walking an attacker's repository.

**Revision.** Stream `git log -p` line by line. Clone with `--no-checkout --filter=blob:none --depth`, `core.hooksPath=/dev/null`, templates disabled. Run clone and history scan **inside the Week-1 container** with no network after fetch. The launcher already exists; reuse it.

### 5.5 An unsalted SHA-256 of a credential is an oracle in an exported artifact

`SecretFingerprint` stores the full unsalted `sha256`, and `build_finding` writes it into the SARIF evidence excerpt — SARIF that goes into CI logs, a client's pipeline, GitHub. For any guessable or previously-leaked credential, an unsalted hash confirms a guess instantly.

B4 requires fingerprints only, encrypted at rest, with a retention limit and automatic deletion. **The retention limit and automatic deletion are absent from the schema and from every plan.**

**Revision.** HMAC-SHA256 with a per-installation key for anything *exported*; keep the raw digest local to the database if cross-scan correlation needs it. Truncate to 16 hex characters in SARIF and HTML. Add `secret_finding.expires_at` with a documented default retention and a `purge` command, and assert deletion in a test. That closes B4, which is currently open.

Add explicit placeholder detection. `entropy ≥ 3.0 ∧ length ≥ 16` fires on file paths, URLs, UUIDs and `"your-api-key-here-replace-me"` — placeholders are the dominant content of public `.mcp.json` files, so this is a heavy false-positive source in the one check class with published prevalence behind it. And `SECRET_PATTERNS` is declared in the Task-21 interface list but never implemented: add real prefix patterns (`sk-`, `ghp_`, `AKIA`, `xoxb-`, `glpat-`, …), which raise precision far more than entropy does.

### 5.6 The passive/active boundary is a naming convention, not a boundary

`ScanContext` hands every check a live `transport`. Any check can call `transport.request(...)`. The `requires_auth` flag is enforced once, in `applicable()`, on the check's own honest self-declaration. Hard constraint 1 says *enforced in code*.

**Revision.** Give passive checks a read-only view — a `RawResponses` object with no transport at all. Only checks the registry has authorised receive a `ProbeTransport` capability object, which additionally refuses methods outside an allowlist. Capability-passing rather than flag-checking; it is less code than the current arrangement and the guarantee becomes structural. Then `test_passive_checks_cannot_reach_the_network` is a real test.

### 5.7 Ecosystem-specific extraction hardening

Week 4 Task 3's guards are good — traversal, symlink, member cap, uncompressed cap. Gaps: **hardlink** members (`tarfile.LNKTYPE`) escape the same way symlinks do; device and FIFO members; no per-file size cap (one 250 MB member passes a 256 MB total); no compression-ratio bound.

Python 3.12 ships `tarfile` extraction filters. `extractall(filter="data")` rejects traversal, symlinks, hardlinks, devices and setuid bits, and is maintained upstream — strictly better than a hand-rolled member walk, and less code. Keep the size caps and the `zipfile` path; drop the hand-rolled member inspection.

`test_the_module_never_executes_an_artifact` greps the source for `"subprocess"`, `"importlib"` and friends. That is a lint dressed as a proof and will pass while producing false confidence. Keep it, but add the assertion that matters: that the extraction path uses the `data` filter.

---

## 6. Free differentiator: five surfaces the specification hands you

The design read the changelog. It did not read the specification pages beneath it. Each of the following is normative, deterministic, unshipped by any inventoried scanner, and directly on the (d) thesis.

### 6.1 `icons` — an entirely new attack surface, with the spec's own MUSTs attached

`2026-07-28` defines `icons` on `Implementation`, `Tool`, `Prompt` and `Resource`, with `src` as an HTTP(S) URL or a `data:` URI, and lists explicit consumer requirements: reject `javascript:`, `file:`, `ftp:`, `ws:` and local app schemes; disallow cross-origin redirects; fetch without credentials; verify same-origin with the server; validate content type by magic bytes; bound image and content size; treat SVG as executable content.

Every one of those is a passive check over the tool listing. `checks/revision/icon_source.py` writes itself, cites the spec section directly, and no competitor has it. **The scanner must not fetch icons itself** — that is unsolicited third-party traffic and, for a census, a constraint violation.

### 6.2 `Origin` validation and localhost binding — the deployment posture you dropped

The transport spec: servers **MUST** validate the `Origin` header and respond `403` when it is present and invalid; when running locally they **SHOULD** bind to `127.0.0.1` rather than `0.0.0.0`; without these, *"attackers could use DNS rebinding to interact with local MCP servers from remote websites."*

Differentiator (a) was dropped as "taken by funded competitors" — but this specific, spec-mandated, locally-testable slice is not taken, needs no endpoint agents, and is a genuine deployment-posture finding. `static/origin_validation` (send an `Origin` that should be rejected — scope-gated) and `static/bind_address` (observable for a local target). Two checks, high signal.

### 6.3 OpenTelemetry `_meta` keys — an unexamined data path

`traceparent`, `tracestate` and `baggage` are reserved in `_meta`. `baggage` is an arbitrary key-value carrier that flows straight into an observability backend — a log-injection and data-exfiltration path with no scanner coverage anywhere, and one check over what a server echoes.

### 6.4 Deterministic tool ordering — the v2 subscription's precondition

Servers **SHOULD** return tools from `tools/list` in a deterministic order. A server that does not breaks description-hash drift diffing, which is the v2 product. Checking it costs two `tools/list` calls and protects the subscription whose schema you are already pre-building.

### 6.5 Unsolicited task handles

The Tasks extension now allows servers to return task handles **unsolicited, without per-request opt-in**. A handle the client never asked for, arriving in model context, is exactly the `state_handle_exposure` threat model — and it is the new part.

---

## 7. Performance and efficiency

### 7.1 One container per JSON-RPC request

`StdioTransport.request` launches a fresh container per request. The `ponytail:` note justifies it from statelessness — but the specification's statelessness section says the opposite about process lifetime: *"an open connection, such as a STDIO process, is not a conversation or session: clients may interleave unrelated requests on the same transport."* Statelessness permits a long-lived process; it does not require a new one per call.

The cost is not only latency:

- **Correctness.** `2026-07-28` says cross-request state **MUST** be an explicit server-minted handle. A handle minted in container A is meaningless in container B, because the server's backing state died with the container. Multi-step probes — `confused_deputy` across tool boundaries, `path_traversal` observing a filesystem effect in tmpfs — cannot work.
- **Throughput.** ~5 launches per minimal scan (§2.6). The eval harness at 17 cases × 3 requests ≈ 51 launches per CI run; with MCPTox's 1,312 cases it is **~4,000 launches**, which is not runnable in CI.
- **Latency per request.** `subprocess.run(input=…, capture_output=True)` reads until process exit. A well-behaved server exits at EOF, but a server driven by an event loop that ignores EOF blocks for the **full `timeout_s`** on every request.

**Revision.** One long-lived container per scan with a persistent stdin/stdout pipe and per-request framing — which is what the stdio transport is. Containment is per-container and unchanged; teardown at scan end; hard wall-clock budget for the whole scan. For the eval harness, use the fixture's already-exposed in-process `handle()` — the plan built it for exactly this and then does not use it. That alone makes MCPTox in CI feasible.

### 7.2 The seccomp profile will break real servers, and cannot run on ARM

The hand-written profile uses `SCMP_ACT_ERRNO` as default with ~90 allowed syscalls. CPython needs more — `unlinkat`, `rt_sigsuspend`, `restart_syscall`, `membarrier`, `clock_nanosleep`, `socketpair`, `mremap`, `eventfd2`, `renameat2`, `ftruncate`, `getgroups`, `sched_getparam` among them. Failures surface as `EPERM` in confusing places and are indistinguishable from protocol errors — a scanner that reports findings caused by its own sandbox is worse than one with no sandbox.

`archMap` covers only `SCMP_ARCH_X86_64`. Any ARM host — Apple Silicon, ARM CI runners — fails outright.

**Revision.** Use Docker's **default** seccomp profile, which already blocks the dangerous set (`mount`, `ptrace`, `bpf`, `kexec`, `reboot`, keyring calls) and is battle-tested across architectures, combined with `--cap-drop ALL --security-opt no-new-privileges --network none --read-only --pids-limit`. Keep the custom profile as an **optional** hardening flag with a test proving a real Python MCP server still runs under it.

Two adjacent launcher fixes: set `--env HOME=/tmp` (with `--read-only` there is no writable home, and Node and Python tooling both write to `~/.cache`), and add `--ulimit nofile`.

### 7.3 `npx`/`uvx` servers cannot be scanned at all

The most common stdio invocation in the wild is `npx -y @scope/server`, which **needs network to fetch the package**. With `--network none` on every launch, every such server fails.

**Revision.** Two-phase launch: materialise the package in a build step with network, into an image or a read-only layer; then run with `--network none`. Document it, and record which phase each target used — "we could not scan `npx` servers" would be a coverage hole that silently shapes the census.

### 7.4 Smaller efficiency items

- `descriptions.shadowing._cross_references` is O(n²) with `re.escape` + `re.search` per pair over full descriptions. A 200-tool server is 40,000 regex searches with no compiled-pattern cache. Build one alternation of tool names, compile once, scan each description once.
- Every check constructs `Claim(observed_at=datetime.now(UTC))` at *finding* time, not observation time. In a provenance product, timestamp the observation and let findings inherit it.
- `Fingerprint`/`FeatureSet`/`ScanContext` are recomputed per check where they could be computed once (§2.6).
- `census.paginate` sleeps a fixed 500 ms. Tier 1 at ~40 pages is fine; the ~1,200 artifact fetches at 500 ms each plus download time is the real cost. Parallelise artifact fetches with a bounded pool and a per-host rate limit — the politeness constraint is per-host, not global.
- `requires_features: frozenset[Feature] = field(default_factory=lambda: frozenset({...}))` in 23 checks. `frozenset` is immutable, so `dataclasses` accepts it as a plain default. Drop the `default_factory` boilerplate.

---

## 8. Revised gates

The existing gates are good in structure — they name evidence, not intentions. These are the corrections and additions.

### Week 1

- `agent-perimeter scan` fingerprints the fixture at `2025-11-25` and `2026-07-28` **over stdio**. The HTTP path cannot reach a legacy server until `legacy_sse` lands in Week 2 — say so rather than implying otherwise.
- **New:** a request-shape conformance test passes — `_meta` inside `params`, `MCP-Protocol-Version` header present and matching, `Mcp-Method` correct, `Mcp-Name` present only for the three methods and sourced from `params` (§1.3).
- **New:** the containment suite passes with Docker's **default** seccomp profile, and a real Python MCP server runs to completion inside it (§7.2).
- **New:** one long-lived container per scan; a multi-request sequence observes state the server set on an earlier request (§7.1).
- **New:** an integration test asserts the observed `FeatureSet` for each fixture configuration — no feature is asserted that was not observed (§2.1).
- Amend the competitive-verification step: clone `snyk/agent-scan`, `cisco-ai-defense/mcp-scanner` and **`highflame-ai/ramparts`** (the `getjavelin` path is a redirect). Grep for `2026-07-28`, `server/discover`, `resultType`, `cacheScope`, `x-mcp-header`, `-32020`, `Mcp-Protocol-Version`. Record commit SHAs and retrieval dates in `docs/methodology.md`.
- The B12 reading must produce a committed artifact: `docs/threat-model.md` with the two or three reproduced attacks written up. Eight hours with no artifact is unverifiable, which is not a standard this project can hold others to and not itself.

### Week 2

- **SARIF emits both `physicalLocation` and `logicalLocations`**, and the anchored artifact exists on disk after a scan (§1.1).
- The GitHub render screenshot is captured via a **throwaway public repository**, with its URL and date recorded (§1.2).
- `revision.header_body_mismatch` is scope-gated and a refusal test proves it — Week 2 ships an active probe and the gate must say so.
- Every check cites at least one entry from an **approved scheme** (OWASP LLM / OWASP MCP / CoSAI / NSA CSI / MITRE ATLAS); `mcp-spec` alone does not satisfy DoD 2 (§2.7).
- Every CWE cited resolves in a registered CWE table.
- A raising check does not abort the scan; errored checks appear in the summary with a reason (§2.4).
- Ingest limits are enforced and exceeding one produces a finding about the target (§5.1).
- `_config` and `_env` are wired to real CLI options, and the `secrets/*` checks fire in an end-to-end run (§2.5).
- Secret fingerprints exported to SARIF are HMAC'd and truncated; `secret_finding` carries a retention field and a purge path (§5.5).
- The fixture flaw matrix is complete and every corpus case's flaw exists (§4.4).
- `revision.param_header_injection` is replaced by the four annotation checks of §1.8.

### Week 3

- The eval harness calls the **real** `fingerprint(transport)` (§4.3).
- Scoring is closed-world: unlisted checks default to `expect_clean` (§4.1).
- The harness runs with a fixture-scoped `ScopeFile`, so the five auth-gated checks are measured (§4.4).
- Degraded mode is measured by **findings produced**, not registrations (§4.5).
- Policy predicates are registered checks, subject to the citation gate and skip accounting (§4.4).
- `active/path_traversal` states its limitation: canary confirmation works only where the scanner placed the canary. Against a real target it degrades to a differential-response probe, and the finding says which mode produced it.
- `active/ssrf`'s current design (`http://127.0.0.1:9/…`) cannot confirm anything — there is no observation channel. Either add an out-of-band listener the operator runs, or use differential timing/error signals, or mark it `info` and say what it does and does not prove.
- `Derivation.NAME` exists and no name-regex check claims `SCHEMA` (§3).
- MCPTox is licence-checked before it is depended on; its homogeneity limit is in the methodology (§4.4).

### Week 4

- The registry cursor field is `nextCursor`; `version=latest` is used; the population is de-duplicated by name; a single-page census cannot be reported as complete (§1.4).
- `distribution` is recorded per record, and `remote_only` is a named, counted stratum (§1.4).
- The headline claim in the report matches the measured population, as a **two-stratum estimate whose intervals are reported separately and never pooled** (§1.5).
- **Tier 3 sends exactly one `server/discover` per sampled host and nothing else**; the seed and frame snapshot are published; the opt-out list is consulted before every request; `docs/security.md` is published before the first request goes out (§1.5).
- **The SDK-pin inference is ground-truthed against n = 30 live-fingerprinted packages, and the agreement rate is published as the basis for `ARTIFACT_CONFIDENCE`** (§1.6).
- **A real-world precision sample of n = 100 registry servers is manually adjudicated, and precision is published from it — separately from fixture-corpus recall** (§4.2).
- No Docker socket appears in any compose file (§1.7).
- Clone and history-scan of untrusted repositories run inside the container, with hooks and templates disabled and streamed output (§5.4).
- `test_passive_only` walks the import graph **transitively**, not one level deep.
- Tier-2 `n` is per ecosystem and the report says so; given the ~29:1 npm:PyPI split, the PyPI "top n" is effectively a census of PyPI and is reported as such.

---

## 9. What the plans get right

Recording this because a revision that only lists defects is not an accurate assessment, and several of these are better than the industry norm.

- **`test_passive_only.py`** — enforcing a hard constraint by walking the import graph with `ast`, so it survives a contributor who never read the plan. Make it transitive and it is exemplary.
- **Aggregate-only enforced structurally** — `CensusRecord` instances never reach the template context, so the guarantee is not a review convention.
- **`unknown` is never folded into a denominator**, and `Aggregate.n` documents why in one line.
- **`TERM_DEFINITIONS`**, and the test that every reported term is defined and appears in the output.
- **The test that the word "vulnerable" never appears** in the census report. The brief's central insight turned into a mechanical gate.
- **`secret_finding.validated CHECK (validated = false)`** — a hard constraint as a database invariant that surfaces in a migration diff.
- **`Undefined is not zero`** in the scorer, with `n/a` rather than `0.00`.
- **The MCPTox re-use note**, and the test asserting it states the divergence from the paper's own use.
- **The adversarial-corpus test design** — the stub returns `UNDETERMINED` regardless of input, so any content-derived verdict diverges. Right shape for proving no code path parses attacker text for a verdict. (It proves nothing about a *real* model, though — B6's actual requirement needs a recorded-cassette test against a live provider.)
- **"the guard has been seen to fail when deliberately broken"** in the Week-4 gate — mutation-style verification of a safety control, which almost nobody does.
- **The descope lever decided in advance**, with the explicit statement that tier 1 is never what gets cut.
- **Severity discipline** in `deprecated_features` and `conformance_mismatch`, with the reasoning written down. The problem is that the same discipline is abandoned in `descriptions/` and `static/` — §3 asks for consistency, not for a new idea.

---

## 10. Open decisions

1. ~~**Census coverage of remote-only servers (§1.5).**~~ **Decided 29 August 2026:** the narrowed artifact claim for the package stratum **plus a Tier-3 sample of n = 100 `remote_only` endpoints**, one `server/discover` each, under the registry-collection rules — reported as two strata with separate intervals, never pooled. Full resolution, Tier-3 constraints and the revised passive-only guarantee are in §1.5.
2. ~~**MCPTox licence.**~~ **Decided 29 August 2026:** re-checked live — `gh api repos/zhiqiangwang4/MCPTox-Benchmark` returns `license: null`, no `LICENSE` file exists in the root tree, and the README asserts no licence. Confirmed absent, not merely unasserted. Week 3's adapter **must not vendor or redistribute** the dataset. Keep the "operator supplies a path" design as the only depended-on interface, and add to `docs/methodology.md`: *"MCPTox (arXiv 2508.14925) carries no licence as of 29 August 2026; results are reproducible only by a reader who independently obtains the dataset from `github.com/zhiqiangwang4/MCPTox-Benchmark` and supplies its path."* Full evidence in §0.
3. **Real-world precision adjudication effort (§4.2).** n = 100 manually adjudicated is roughly a day. It is the difference between a published number a sceptic dismantles and one they cannot. Placed in Week 4; if the week is tight, it displaces the tier-2 deep dive before it displaces anything else.

All three open decisions are now resolved. Nothing in this document remains undecided.
</content>
