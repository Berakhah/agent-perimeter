/**
 * Thin typed client for the Task 9 API (`agent_perimeter/api/`).
 *
 * Types match the real FastAPI response shapes read directly from
 * `agent_perimeter/api/{scans,census,schemas}.py`, not the plan's earlier
 * sketch (task-10 pre-flight ruling 3). `findings`/`graph` stay loose
 * (`unknown[]`) on purpose -- Task 11+ defines the narrower shape once a
 * screen actually needs it; inventing one here would just be a second,
 * possibly-drifting copy of the backend's domain models.
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

export function getFindings(id: string): Promise<unknown[]> {
  return request(`/api/scans/${id}/findings`);
}

export function getGraph(id: string): Promise<unknown[]> {
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
