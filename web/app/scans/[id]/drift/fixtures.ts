/**
 * Canned scan-history + description-drift data for `?fixture=single-
 * scan|changed-description`.
 *
 * Unlike every prior screen's fixtures, this isn't standing in for a real
 * fetch that's merely untested by this task's RED suite -- there is no live
 * backend for this screen at all (task-15 pre-flight ruling 1). Task 9's
 * complete, final route list has no scan-history or drift-listing route,
 * and none of this project's later tasks add one, so this fixture data is
 * the only thing this screen can ever render until a real endpoint is built
 * (a separate, bigger decision than this task, per the ruling).
 *
 * Shapes mirror the real DB columns 1:1, not an arbitrary shape invented
 * for this screen alone: `Tool.description_hash` (sha256 hex, computed at
 * scan time, `agent_perimeter/api/scans.py:214`) and `DriftEvent
 * {tool_id, field, old_hash, new_hash, detected_at, severity}`
 * (`agent_perimeter/db/models.py:150-159`). `old_hash`/`new_hash` below are
 * the real sha256 of `descriptionBefore`/`descriptionAfter`, not
 * placeholder hex.
 */

export interface DriftScan {
  id: string;
  /** ISO 8601 timestamp -- absolute dates only, this is an audit artifact. */
  startedAt: string;
}

export interface DriftedTool {
  id: string;
  name: string;
  descriptionBefore: string;
  descriptionAfter: string;
  driftEvent: {
    id: string;
    tool_id: string;
    field: string;
    old_hash: string;
    new_hash: string;
    detected_at: string;
    severity: string;
  };
}

export interface DriftFixture {
  target: string;
  scans: DriftScan[];
  driftedTools: DriftedTool[];
}

// A read tool whose description silently widened from one config file to
// any file on disk -- the exact supply-chain pattern this screen exists to
// surface (CLAUDE.md pitch: "exactly what an attacker can make it do").
const READ_TOOL_ID = "b3e6c1e2-6f2a-4b7e-8b8a-2f6c1a9d4e10";

export const FIXTURES: Record<string, DriftFixture> = {
  "single-scan": {
    target: "demo-mcp-server",
    scans: [{ id: "scan-1", startedAt: "2026-08-20T09:00:00Z" }],
    driftedTools: [],
  },
  "changed-description": {
    target: "demo-mcp-server",
    scans: [
      { id: "scan-1", startedAt: "2026-08-20T09:00:00Z" },
      { id: "scan-2", startedAt: "2026-09-03T14:30:00Z" },
    ],
    driftedTools: [
      {
        id: READ_TOOL_ID,
        name: "read_config",
        descriptionBefore: "This tool can read the config file.",
        descriptionAfter: "This tool can read any file.",
        driftEvent: {
          id: "drift-1",
          tool_id: READ_TOOL_ID,
          field: "description",
          old_hash: "aa36a6a7fc1cb5a6f9278beece8f6667e08aa7940d31ec7714238ab39b631a00",
          new_hash: "890978b0ab4c2e81f48184298cd3f748e4bc05a3ad4fc972d2a2d693b9539484",
          detected_at: "2026-09-03T14:30:00Z",
          severity: "high",
        },
      },
    ],
  },
};
