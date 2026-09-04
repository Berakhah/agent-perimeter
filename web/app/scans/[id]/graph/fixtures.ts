/**
 * Canned capability-edge data for `?fixture=deputy|mixed-derivation|no-
 * tools` (task-10's `?fixture=` precedent, carried through tasks 11-13). No
 * live backend is reachable from this project's Playwright runs, so this is
 * what drives every RED test in `tests/graph.spec.ts`.
 *
 * `CapabilityEdge` shape matches the real wire format 1:1
 * (`agent_perimeter/model/edge.py`, task-14 pre-flight ruling 1). Fixture
 * mode marks flagged tools directly (`flaggedTools`) rather than simulating
 * the real findings cross-reference -- ruling 1 only binds the production
 * (`graph/page.tsx`'s non-fixture branch) data-loading path.
 */
import type { CapabilityEdge } from "@/src/lib/api";

export interface GraphFixture {
  edges: CapabilityEdge[];
  flaggedTools: string[];
}

const NOW = "2026-09-04T10:00:00Z";

function claim(
  value: unknown,
  method: CapabilityEdge["claim"]["method"],
  derivation: CapabilityEdge["claim"]["derivation"],
  confidence: number | null,
): CapabilityEdge["claim"] {
  return { value, method, derivation, confidence, observed_at: NOW, parents: [], caveat: null };
}

// `list_files` is ordered first so the first Tab press
// (tests/graph.spec.ts "the graph is fully navigable from the keyboard")
// lands on an unflagged, plain-testid `node` -- `sync_to_remote` is the
// confused-deputy tool: fs_read (schema-confirmed) + net_out
// (probe-confirmed) trips `policy.confused_deputy`
// (`agent_perimeter/graph/policy.py`).
const DEPUTY_EDGES: CapabilityEdge[] = [
  {
    tool: "list_files",
    capability: "fs_read",
    derivation: "schema",
    rationale: "input schema accepts a directory path and returns file contents",
    claim: claim("list_files", "deterministic", "schema", 0.9),
  },
  {
    tool: "sync_to_remote",
    capability: "fs_read",
    derivation: "schema",
    rationale: "input schema accepts a local file path before uploading it",
    claim: claim("sync_to_remote", "deterministic", "schema", 0.9),
  },
  {
    tool: "sync_to_remote",
    capability: "net_out",
    derivation: "probe",
    rationale: "probe confirmed an outbound HTTPS POST to a caller-supplied URL",
    claim: claim("sync_to_remote", "deterministic", "probe", 0.97),
  },
];

const MIXED_DERIVATION_EDGES: CapabilityEdge[] = [
  {
    tool: "read_config",
    capability: "fs_read",
    derivation: "schema",
    rationale: "input schema accepts a config file path",
    claim: claim("read_config", "deterministic", "schema", 0.9),
  },
  {
    tool: "notify_webhook",
    capability: "net_out",
    derivation: "description",
    rationale: 'tool description says it "posts a summary to the configured webhook"',
    claim: claim("notify_webhook", "model", "description", 0.65),
  },
  {
    tool: "notify_webhook",
    capability: "net_out",
    derivation: "probe",
    rationale: "probe confirmed an outbound HTTPS POST",
    claim: claim("notify_webhook", "deterministic", "probe", 0.95),
  },
  {
    tool: "backup_db",
    capability: "db_read",
    derivation: "artifact",
    rationale: "a SQL client library is bundled in the server's dependency manifest",
    claim: claim("backup_db", "deterministic", "artifact", 0.6),
  },
];

export const FIXTURES: Record<string, GraphFixture> = {
  deputy: { edges: DEPUTY_EDGES, flaggedTools: ["sync_to_remote"] },
  "mixed-derivation": { edges: MIXED_DERIVATION_EDGES, flaggedTools: [] },
  "no-tools": { edges: [], flaggedTools: [] },
};
