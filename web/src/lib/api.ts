/**
 * Thin typed client for the Task 9 API (`agent_perimeter/api/`).
 *
 * Types match the real FastAPI response shapes read directly from
 * `agent_perimeter/api/{scans,census,schemas}.py`, not the plan's earlier
 * sketch (task-10 pre-flight ruling 3). `findings` (task 13) and `graph`
 * (task 14) are now typed against their real backend shapes; anything a
 * later screen hasn't needed yet stays loose (`unknown[]`) rather than
 * inventing a second, possibly-drifting copy of a backend domain model
 * ahead of need.
 *
 * Base URL: same origin by default (`NEXT_PUBLIC_API_BASE_URL` overrides it
 * for a split frontend/backend deployment). No retry/cache layer -- nothing
 * in this task calls for one.
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "";

export type ScanMode = "passive" | "active";

export interface ScopeFileInput {
  target: string;
  authorising_party: string;
  /** ISO date (YYYY-MM-DD). Defaults server-side to today when omitted. */
  authorised_on?: string;
  attestation: string;
  /** ISO date (YYYY-MM-DD). */
  expires_on?: string;
}

export interface ScanRequest {
  target: string;
  mode?: ScanMode;
  scope_file?: ScopeFileInput;
}

export interface ScanAccepted {
  id: string;
  status: "accepted";
}

export interface ScanStatus {
  id: string;
  status: "running" | "completed" | "errored";
  revision_claimed?: string | null;
  features_observed?: string[];
  findings_count?: number;
  skipped_count?: number;
  errored_count?: number;
}

/** 400 body for a non-http(s) target (`POST /api/scans` classifies before any transport logic runs). */
export interface UnsupportedTargetError {
  error: "unsupported_target";
  message: string;
}

export interface CensusRun {
  id: number;
  started_at: string;
  finished_at: string | null;
  population_size: number;
  fetch_failures: number;
  tool_version: string;
  method_hash: string;
  tier2_n: number;
  registry_endpoint: string;
}

/** One completed-check frame from `GET /api/scans/{id}/events`. */
export interface ScanCheckEvent {
  check_id: string;
  status: "passed" | "errored";
  elapsed_ms: number;
  phase: string;
  completed: number;
  total: number;
}

/**
 * The terminal frame. A distinct shape from `ScanCheckEvent`, not that shape
 * plus one field -- verified directly against `agent_perimeter/api/events.py`
 * (`EventLog.finish`), which never carries `check_id`/`status`/`elapsed_ms`/
 * `phase` on this frame.
 */
export interface ScanTerminalEvent {
  terminal: true;
  completed: number;
  total: number;
  skipped: Array<{
    check_id: string;
    reason: "feature_absent" | "not_authorised" | "model_unavailable";
    detail: string;
  }>;
}

export type ScanEvent = ScanCheckEvent | ScanTerminalEvent;

export function isTerminalEvent(event: ScanEvent): event is ScanTerminalEvent {
  return "terminal" in event && event.terminal === true;
}

class ApiError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`API request failed with status ${status}`);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => undefined);
    throw new ApiError(response.status, body);
  }
  return response.json() as Promise<T>;
}

export function createScan(body: ScanRequest): Promise<ScanAccepted> {
  return request("/api/scans", { method: "POST", body: JSON.stringify(body) });
}

export function getScan(id: string): Promise<ScanStatus> {
  return request(`/api/scans/${id}`);
}

/**
 * Wire shape of `agent_perimeter/model/finding.py::Finding`, serialized as-is
 * by `GET /api/scans/{id}/findings` (`jsonable_encoder`, no field renaming --
 * task-13 pre-flight ruling 1). Duplicated from `_bok-ui.tsx`'s
 * `Method`/`Derivation` string unions rather than importing them: this is
 * the API layer's copy of a *backend* enum's wire values, not a UI concern,
 * and the two files stay independently correct even though the string sets
 * happen to line up today.
 */
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ClaimMethod = "deterministic" | "model" | "human" | "derived";
export type ClaimDerivation = "schema" | "name" | "description" | "probe" | "artifact";

export interface FindingClaim {
  value: unknown;
  method: ClaimMethod;
  derivation?: ClaimDerivation | null;
  confidence?: number | null;
  /** ISO 8601 timestamp. */
  observed_at: string;
  parents?: FindingClaim[];
  caveat?: string | null;
}

export interface FindingEvidence {
  kind: "transcript" | "excerpt" | "screenshot" | "diff";
  excerpt: string;
  highlight?: [number, number] | null;
  redacted?: boolean;
}

export interface FindingLocation {
  uri: string;
  line?: number;
}

export interface Finding {
  check_id: string;
  severity: FindingSeverity;
  title: string;
  /** "CWE-nnn". */
  cwe: string;
  /** "scheme:id", e.g. "owasp-llm:LLM01" (`checks/taxonomy.py`). */
  taxonomy_refs: string[];
  evidence: FindingEvidence;
  reproduction: string;
  claim: FindingClaim;
  confidence?: number | null;
  location?: FindingLocation | null;
}

export function getFindings(id: string): Promise<Finding[]> {
  return request(`/api/scans/${id}/findings`);
}

/**
 * Wire shape of `agent_perimeter/model/edge.py::CapabilityEdge`, serialized
 * as-is by `GET /api/scans/{id}/graph` (`jsonable_encoder`, no field
 * renaming -- task-14 pre-flight ruling 1). There is no separate top-level
 * `nodes` array: the frontend derives tool nodes and the 7 fixed capability
 * nodes from this flat edge list itself.
 */
export type Capability =
  | "fs_read"
  | "fs_write"
  | "net_out"
  | "exec"
  | "secret_read"
  | "db_read"
  | "db_write";

export interface CapabilityEdge {
  tool: string;
  capability: Capability;
  /** Always present on the edge itself, unlike the (optional) `claim.derivation`. */
  derivation: ClaimDerivation;
  claim: FindingClaim;
  rationale: string;
}

export function getGraph(id: string): Promise<CapabilityEdge[]> {
  return request(`/api/scans/${id}/graph`);
}

export function getSarifReport(id: string): Promise<Record<string, unknown>> {
  return request(`/api/scans/${id}/report.sarif`);
}

export function getCensusRun(id: number): Promise<CensusRun> {
  return request(`/api/census/runs/${id}`);
}

/**
 * Subscribes to `GET /api/scans/{id}/events` (SSE) and returns an unsubscribe
 * function. `onEvent` fires per frame in stream order; the caller checks
 * `isTerminalEvent` to know when the stream is done (the server never closes
 * the connection itself for a still-open EventSource, so the caller decides
 * when to unsubscribe).
 */
export function subscribeToScanEvents(
  id: string,
  onEvent: (event: ScanEvent) => void,
  onError?: (error: Event) => void,
): () => void {
  const source = new EventSource(`${BASE_URL}/api/scans/${id}/events`);
  source.onmessage = (message) => {
    onEvent(JSON.parse(message.data) as ScanEvent);
  };
  if (onError) source.onerror = onError;
  return () => source.close();
}

export { ApiError };
