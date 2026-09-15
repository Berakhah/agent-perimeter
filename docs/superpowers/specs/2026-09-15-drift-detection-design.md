# Agent Perimeter — Description Drift Detection

**Date:** 15 September 2026
**Status:** design approved in brainstorming; awaiting implementation plan
**Scope:** the v2 "drift" surface that Weeks 1–4 stubbed (brief §7 screen 5, §9 `drift_event`, §11 "continuous monitoring").
**Supersedes:** the `web/app/scans/[id]/drift/page.tsx` ruling that "there is no live backend for this screen".

---

## 1. Why

A point-in-time scan cannot catch the rug pull: a server whose tool
descriptions are benign on day one and instruct the model to exfiltrate on
day thirty. The brief calls this "the actual attack". Weeks 1–4 put
`Tool.description_hash` and the `drift_event` table into the v1 schema so
this could be built without a retrofit; nothing reads or compares them yet.

## 2. Decisions taken (brainstorming, 15 Sep 2026)

| # | Decision | Chosen | Rejected |
|---|---|---|---|
| D1 | What triggers a rescan | **Compare-on-scan.** Every scan of a target is compared to a baseline; rescans come from the CLI, the API, or a CI cron the operator owns. No scheduler, no long-running process, $0 recurring cost. | Built-in scheduler (always-on process, edges toward hosting an internet scanner — brief B2). GitHub Action (deferred, not rejected; see §10). |
| D2 | What counts as drift | **Description, `input_schema`, `annotations`, tool added, tool removed** — per tool. | Description only (misses schema-based rug pulls). Server-level changes (dilute the alert; not "a tool silently changed"). |
| D3 | Persist description text | **Yes** — `tool.description` column, alongside the hash. Needed for the word-level diff. | Hash only (screen cannot show what changed). |
| D4 | How drift surfaces | **Drift events + a first-class `Finding`** from a `drift.description_drift` check, so drift lands in the findings list, SARIF, HTML and the CLI summary. | Events + API route only (a nightly CI cron would have nothing to fail on). |
| D5 | Where the baseline comes from | **Pluggable snapshot source.** A portable `ToolSnapshot`; the API loads it from Postgres, the CLI from a file. The check is pure. | DB-only (forces Postgres into every CI job and makes the CLI stateful). Standalone `drift` command only (no finding, no SARIF). |

Routine calls made without asking: same target = exact `target_ref` string
match; baseline = most recent *finished* prior scan of that target unless
pinned; snapshot schema is versioned.

## 3. Hard-rule check

| Rule | Effect on this design |
|---|---|
| 1 No active probe without scope | Drift adds no probe. A rescan obeys the same `require_scope` gate as any scan. The `drift` CLI command does no network I/O. |
| 2 Public-registry scanning is passive | Unchanged. Drift is only computed for targets the operator scans; the census does not compare or store descriptions per this feature. |
| 3 Never validate a secret | Unchanged. Snapshots contain descriptions/schemas/annotations, never scan-time secrets. |
| 4 stdio in a locked container | Unchanged; the rescan launches the same way. |
| 5 Analysed content never reaches a tool-capable context | Descriptions are stored, diffed and rendered **as data**. The compare engine is pure Python; the check has `requires_model=False`. The diff page renders text nodes, never HTML. |
| 6 Every finding cites CWE + taxonomy | `CWE-494` primary; `owasp-mcp:MCP03`, `owasp-llm:LLM01`, `mcp-spec:2026-07-28-security`. See §6.3 — MCP03's title and URL must be verified live before the row is added to `taxonomy.yaml`. |
| 7 No weaponisation | Drift reports a diff and stops. |
| 8 No named third-party server in public output | Drift output is per-operator, never aggregated into the census report. |
| Determinism budget | Model-free. Degraded-mode surviving-class count rises by one. |

## 4. Data model

### 4.1 `agent_perimeter/model/snapshot.py`

```python
class SnapshotTool(BaseModel):
    name: str
    description: str
    input_schema: dict[str, object]
    annotations: dict[str, object]
    description_hash: str   # sha256(description.encode())
    schema_hash: str        # sha256(canonical_json(input_schema))
    annotations_hash: str   # sha256(canonical_json(annotations))

class ToolSnapshot(BaseModel):
    version: Literal[1] = 1
    target: str
    taken_at: datetime      # ISO-8601, UTC
    scan_id: str | None = None
    tools: list[SnapshotTool]

    @classmethod
    def from_tools(cls, target, tools: list[ToolRecord], *, taken_at, scan_id=None) -> ToolSnapshot: ...
```

`canonical_json` = `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
Key reordering must **not** register as drift; a golden test proves it.
`description_hash` uses the exact same expression `api/scans.py::_persist`
uses today, so rows written before this feature compare correctly.

### 4.2 `agent_perimeter/model/drift.py`

```python
class DriftField(StrEnum):
    DESCRIPTION = "description"
    INPUT_SCHEMA = "input_schema"
    ANNOTATIONS = "annotations"
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"

DRIFT_SEVERITY: dict[DriftField, Severity] = {
    DriftField.DESCRIPTION: Severity.HIGH,
    DriftField.TOOL_ADDED: Severity.HIGH,
    DriftField.INPUT_SCHEMA: Severity.MEDIUM,
    DriftField.ANNOTATIONS: Severity.MEDIUM,
    DriftField.TOOL_REMOVED: Severity.LOW,
}

class DriftEvent(BaseModel):
    tool_name: str
    field: DriftField
    old_hash: str | None      # None for TOOL_ADDED
    new_hash: str | None      # None for TOOL_REMOVED
    old_value: str | None     # description text or canonical JSON; carried in memory only
    new_value: str | None
    severity: Severity
    detected_at: datetime
```

### 4.3 Migration `0006_drift_text`

- `tool.description TEXT NULL` — nullable so pre-feature rows survive; every new write fills it.
- `drift_event.scan_id VARCHAR(36) NOT NULL REFERENCES scan(id)` and
  `drift_event.baseline_scan_id VARCHAR(36) NOT NULL REFERENCES scan(id)`.
  The table is empty today, so `NOT NULL` needs no backfill.
- `drift_event.field` stays `String(32)` — the longest value is 12 characters.
- Index `(scan_id)` on `drift_event`; index `(target_ref, finished_at)` on `scan` for the baseline lookup.
- Downgrade drops the three columns and two indexes. The clean-machine smoke script's `(head)` check covers the new head automatically.

Old/new **text is not stored on the event row**. The read path joins to the
baseline scan's `tool` rows for it (§7.4). One copy of each description per
scan, not two.

## 5. Compare engine — `agent_perimeter/drift/`

### 5.1 `compare.py`

```python
def compare(baseline: ToolSnapshot, current: ToolSnapshot, *, now: datetime) -> list[DriftEvent]: ...
```

- Raises `ValueError` if `baseline.target != current.target`. Callers must never compare across targets.
- Tools matched by `name`. Names in `current` only → `TOOL_ADDED`; in `baseline` only → `TOOL_REMOVED`; matched → one event per differing hash among the three.
- Output ordered by `(tool_name, field)` so SARIF `partialFingerprints`, golden files and the CLI diff are stable regardless of input order.
- Pure: no I/O, no clock (`now` injected).

### 5.2 `render.py`

`word_diff(old: str, new: str) -> list[tuple[Literal["equal","insert","delete"], str]]`
using `difflib.SequenceMatcher` over whitespace-split tokens. Used by the
check's evidence excerpt and the `drift` CLI command. The web keeps its own
`DiffView`.

## 6. The check — `agent_perimeter/checks/drift/description_drift.py`

### 6.1 Declaration

| Property | Value |
|---|---|
| `id` | `drift.description_drift` |
| `cwe` | `CWE-494` (Download of Code Without Integrity Check — the tool surface changed underneath a consumer that had no way to notice) |
| `taxonomy_refs` | `("owasp-mcp:MCP03", "owasp-llm:LLM01", "mcp-spec:2026-07-28-security")` |
| `severity` | `HIGH` (declared ceiling; each finding's severity is the max over that tool's events) |
| `requires_auth` | `False` |
| `requires_model` | `False` |
| `requires_features` | `frozenset()` — applies to every revision |
| `requires_baseline` | `True` — new protocol property, `False` on every other check |

### 6.2 Behaviour

- `run_scan` gains `baseline: ToolSnapshot | None = None`. After `enumerate_tools`, the runner computes `drift_events = compare(baseline, ToolSnapshot.from_tools(...), now=...)` **once** when a baseline is present (else `[]`) and puts the result on both `ScanContext.drift_events` and `ScanOutcome.drift_events`. The check formats; it never re-computes. One computation, so the API persists exactly what the check reported.
- `ScanContext` gains `baseline: ToolSnapshot | None = None` and `drift_events: list[DriftEvent] = []`.
- No baseline → the check is **skipped**, not passed. `checks/registry.py` gains `SkipReason.NO_BASELINE` with detail `"no earlier scan of this target to compare against — pass --baseline (CLI) or scan this target again (API)"`. `applicable()` gains a keyword `has_baseline: bool`; the runner passes `baseline is not None`, and `applicable()` skips any check whose new `requires_baseline` property is `True`. `requires_baseline` is added to the `Check` protocol with a default of `False` on every existing check (a one-line property on the shared base), so the "N checks skipped and why" line stays honest (CLAUDE.md copy rules) and a baseline-less scan never calls `run()`.
- Otherwise: `context.drift_events` grouped by `tool_name`; **one `Finding` per drifted tool**.
  - `title`: `"Tool '<name>' changed since the baseline scan: description, input_schema"` (fields listed in enum order).
  - `severity`: max over the tool's events.
  - `evidence`: the existing `EvidenceKind` used by the description checks; `excerpt` = rendered word diff of the description when it changed, else one line per changed field (`"input_schema: <old_hash[:12]> → <new_hash[:12]>"`). Old and new text appear only inside the excerpt, as data; the finding never interpolates them into any instruction-shaped string.
  - `reproduction`: `agent-perimeter drift <baseline> <current> --tool <name>`. On the CLI the two operands are the snapshot file paths; on the API they are `scan:<id>` references (§8.2).
  - `claim`: a `bok-core` `Claim` asserting `"tool <name> <field> hash changed from <old> to <new>"` per event, with the snapshot(s) as the artefact.
  - `confidence`: `1.0` — a hash comparison is not a heuristic.
  - `location`: `FindingLocation(uri=f"mcp://{target}/tools/{name}")`, or whatever URI convention the description checks use today — match it, do not invent a second one.

### 6.3 Taxonomy row to add

```yaml
- scheme: owasp-mcp
  id: MCP03
  title: Tool Poisoning          # VERIFY LIVE before adding; title/URL pattern assumed from MCP01/07/09/10
  url: https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning
```

If the live entry's title differs, use the live title. If MCP03 is not the
tool-poisoning entry, cite whichever MCP entry is, and record the check in
the plan's verification log (the 29 Aug revision doc sets the precedent).

### 6.4 Registration

Appended to `ALL_CHECKS`. `test_every_check_cites_taxonomy` and the
degraded-mode test pick it up with no test changes beyond the expected
count moving by one.

## 7. API surface — `agent_perimeter/api/scans.py`, new `agent_perimeter/api/drift.py`

### 7.1 Request

`ScanRequest` gains `baseline_scan_id: str | None = None`.

### 7.2 Baseline loading (before `run_scan`)

`_load_baseline(session_factory, target_ref, *, pinned: str | None) -> ToolSnapshot | None`

- Pinned: load that scan; it must exist, be finished, and have the same `target_ref`, else HTTP 422 with a message naming the mismatch. Checked before the scan starts, so a bad pin never burns a container launch.
- Unpinned: the most recent scan `WHERE target_ref = :t AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1`.
- Rebuild a `ToolSnapshot` from that scan's `tool` rows. Rows with `description IS NULL` (pre-0006) get `description=""` and keep their stored `description_hash`; comparison still works because the hash is what is compared.
- DB unreachable or no prior scan → `None`, logged at `info`, scan proceeds. Same best-effort contract as `_persist`.

### 7.3 Persistence (`_persist`)

- `Tool` rows now write `description=tool.description`.
- One `DriftEventRow` per event in `outcome.drift_events`: `scan_id`, `baseline_scan_id`, `tool_id` (the **current** scan's tool row; for `TOOL_REMOVED` the **baseline** scan's tool row), `field`, `old_hash`, `new_hash`, `severity`, `detected_at`.

### 7.4 Read route

`GET /api/scans/{scan_id}/drift` → 200

```json
{
  "scan_id": "…",
  "target_ref": "…",
  "baseline_scan_id": "…",
  "scans": [ { "id": "…", "started_at": "…", "tool_count": 12 } ],
  "drifted_tools": [
    { "name": "…", "field": "description", "severity": "high",
      "old_hash": "…", "new_hash": "…",
      "old_text": "…", "new_text": "…" }
  ]
}
```

- `baseline_scan_id` is `null` and `drifted_tools` is `[]` when the scan had no baseline.
- `scans`: every scan with this `target_ref`, newest first, capped at 20 — the timeline.
- `old_text`/`new_text`: description text for `description` events; canonical JSON for schema/annotation events; `null` for the missing side of added/removed events and for rows that predate 0006.
- 404 if the scan is unknown; 409 if it is still running (same as the other per-scan routes).
- **This is the first route that reads from the database.** Task 9's ruling ("DB is durability/audit only, never the read path") stands for findings/graph/report; drift is history, and the in-process cache cannot hold history across process restarts. The exception is recorded in `docs/open-decisions.md` when this ships.

### 7.5 Web

`web/src/lib/api.ts` gains `getDrift(scanId)`. `drift/page.tsx` replaces the
unconditional empty-state branch with the fetch; `?fixture=` is retained so
Playwright stays hermetic. The empty state's copy is unchanged. `DiffView`
receives `old_text`/`new_text` exactly as the fixtures shape them today.

## 8. CLI surface — `agent_perimeter/cli.py`

### 8.1 `scan` options

| Option | Behaviour |
|---|---|
| `--baseline PATH` | Read a `ToolSnapshot` JSON and pass it to `run_scan`. Refuse (exit 2, before any transport is built) if the file is missing/invalid or `snapshot.target != --target`; the message names both targets and says to pass the matching baseline or omit the flag. |
| `--snapshot PATH` | After the scan completes, write `ToolSnapshot.from_tools(...)` here (`indent=2`, `ensure_ascii=False`). Written even when the scan found nothing — the next run needs it. |
| `--fail-on-drift` | Exit `3` when any `drift.description_drift` finding was emitted. Without `--baseline` the check is skipped and the flag is inert — the summary line says so. Exit-code table: `0` ok, `1` scan error, `2` refused/usage, `3` drift gate tripped (new). |

### 8.2 `drift` command

`agent-perimeter drift BASELINE CURRENT [--tool NAME] [--json]`

- Both operands are snapshot file paths. Runs `compare()`, prints one block per drifted tool: a header line (name, fields, severity) then the word-level diff with `-`/`+` prefixed runs. `--json` emits the `DriftEvent` list. Exit 0 when no drift, 3 when drift, 2 on target mismatch or unreadable file.
- No network. No database. This is the reproduction a sceptic runs with two files and nothing else.
- API findings cite `scan:<id>` operands. `docs/byo-agent.md` gains a two-line note that `GET /api/scans/{id}/drift` returns the text those refer to and that the CLI accepts a snapshot file assembled from it. A DB-to-file `snapshot export` command is **not** in scope (§10).

### 8.3 Security note (`docs/security.md`)

Snapshot files contain attacker-authored description text. They are written
only where the operator names, never logged, and are the scanner's own
output — the secrets checks do not scan them.

## 9. Testing

| Layer | Tests |
|---|---|
| `compare()` | unchanged → `[]`; description only; schema key reorder → `[]`; annotation change; added; removed; mixed on one tool; cross-target `ValueError`; ordering stable across input order. |
| `render.py` | golden word-diff for a rug-pull description (fixture text from the existing adversarial corpus). |
| Check | no baseline → `Skipped(NO_BASELINE)`, not a finding; one finding per drifted tool with max severity; excerpt contains old and new text; `confidence == 1.0`; CWE/taxonomy present (existing sweep). |
| Fixture fleet | `tests/fixtures/servers/drifting-server/` — one server, two builds (`v1`, `v2`) differing only in one tool's description and another tool's schema. End-to-end: scan v1 `--snapshot`, scan v2 `--baseline` → exactly two findings; SARIF golden added. |
| API | `POST /scans` twice on the same target → second has the finding and `drift_event` rows; `GET /drift` returns old/new text; first-ever scan → `baseline_scan_id: null`, empty list; pinned baseline with wrong target → 422; DB down → scan completes, check skipped. |
| CLI boundary | `--baseline` target mismatch → exit 2 before transport; invalid JSON → exit 2; `--fail-on-drift` → exit 3 only when drift found; `drift` command exit codes. |
| Migration | `alembic upgrade head` then `downgrade -1` round-trip against the test Postgres; pre-0006 rows (`description NULL`) still compare by hash. |
| Degraded mode | expected surviving-class count +1; floor still ≥90%. |
| Web | `drift.spec.ts` keeps both fixture cases; adds one live case against a mocked `GET /drift`; keyboard-only; axe zero serious/critical. |
| Coverage | floor 75% unchanged; new modules target ≥95%. |

## 10. Out of scope (recorded so nobody re-decides it by accident)

- A GitHub Action wrapper (`agent-perimeter/scan@v1`). Natural follow-on; needs the marketplace/publishing decision first.
- Any scheduler or "watched targets" table.
- Server-level drift (transport/auth/revision changes).
- Notifications (email/webhook) on drift.
- Exporting a snapshot from the DB via the CLI.
- Census-wide drift across registry runs — cross-run tool-description drift on third-party servers would be a named-server finding and collides with rule 8.
