/**
 * Canned `ScanEvent[]` sequences for `?fixture=streaming|degraded|deterministic`
 * (task-10's `?fixture=` precedent, `findings/page.tsx`). Check ids are real
 * namespaces verified against the Python modules under `agent_perimeter/checks`
 * (task-12 brief); `phase` on each event is the id's namespace prefix, matching
 * `scan_runner.py:258` (`check.id.split(".", 1)[0]`).
 *
 * `descriptions.llm_judge` is the one check the determinism budget lets call
 * a model (CLAUDE.md) -- it never appears as a running check in any of
 * these three fixtures, only as the single skipped entry in `degraded`'s
 * terminal frame. That is deliberate: it is this module's only lever for
 * "a model lane engaged" (`page.tsx` watches for its check id in the
 * arrived-event stream), and the determinism budget makes that the
 * exception, not the rule -- `deterministic` shows the common case,
 * `degraded` shows the one check the model-unavailable path actually skips.
 */
import type { ScanCheckEvent, ScanEvent, ScanTerminalEvent } from "@/src/lib/api";

// 30 real, non-model check ids spanning every phase in the namespace list
// the brief hands us (`active`, `descriptions`, `injection`, `revision`,
// `secrets`, `static`) -- `revision` alone contributes 12, so any 29-slice
// below keeps at least one `revision` row (RED test 1's requirement).
const NON_MODEL_CHECK_IDS = [
  "active.command_injection",
  "active.confused_deputy",
  "active.path_traversal",
  "active.ssrf",
  "descriptions.imperative_injection",
  "descriptions.name_schema_mismatch",
  "descriptions.shadowing",
  "descriptions.unicode_anomaly",
  "injection.agent_adapter",
  "injection.path_proof",
  "revision.cache_scope",
  "revision.conformance_mismatch",
  "revision.deprecated_features",
  "revision.header_annotation_invalid",
  "revision.header_annotation_type",
  "revision.header_annotation_unreachable",
  "revision.header_body_mismatch",
  "revision.issuer_validation",
  "revision.registration_mode",
  "revision.request_state_binding",
  "revision.schema_composition",
  "revision.state_handle_exposure",
  "secrets.config_scan",
  "secrets.env_scan",
  "secrets.history_scan",
  "static.auth_mode",
  "static.cleartext_target",
  "static.scope_breadth",
  "static.session_state",
  "static.token_passthrough",
] as const;

const MODEL_CHECK_ID = "descriptions.llm_judge";

function phaseOf(checkId: string): string {
  const dot = checkId.indexOf(".");
  return dot === -1 ? checkId : checkId.slice(0, dot);
}

function buildCheckEvents(ids: readonly string[], total: number): ScanCheckEvent[] {
  return ids.map((checkId, index) => ({
    check_id: checkId,
    status: "passed",
    elapsed_ms: 30 + ((index * 17) % 90),
    phase: phaseOf(checkId),
    completed: index + 1,
    total,
  }));
}

const STREAMING_IDS = NON_MODEL_CHECK_IDS.slice(0, 29);
const streamingTerminal: ScanTerminalEvent = { terminal: true, completed: 29, total: 29, skipped: [] };
const STREAMING: ScanEvent[] = [...buildCheckEvents(STREAMING_IDS, 29), streamingTerminal];

const DEGRADED_RUNNABLE_IDS = NON_MODEL_CHECK_IDS.slice(0, 28);
const degradedTerminal: ScanTerminalEvent = {
  terminal: true,
  completed: 28,
  total: 29,
  skipped: [
    {
      check_id: MODEL_CHECK_ID,
      reason: "model_unavailable",
      // No "Skipped --" prefix here -- `PhaseGroup` already renders one
      // (`Skipped — {check.detail}`); doubling it up read as
      // "Skipped — Skipped — ...".
      detail: "no model provider is configured for this scan.",
    },
  ],
};
const DEGRADED: ScanEvent[] = [...buildCheckEvents(DEGRADED_RUNNABLE_IDS, 29), degradedTerminal];

const DETERMINISTIC_IDS = NON_MODEL_CHECK_IDS.slice(0, 29);
const deterministicTerminal: ScanTerminalEvent = { terminal: true, completed: 29, total: 29, skipped: [] };
const DETERMINISTIC: ScanEvent[] = [...buildCheckEvents(DETERMINISTIC_IDS, 29), deterministicTerminal];

export const FIXTURES: Record<string, ScanEvent[]> = {
  streaming: STREAMING,
  degraded: DEGRADED,
  deterministic: DETERMINISTIC,
};
