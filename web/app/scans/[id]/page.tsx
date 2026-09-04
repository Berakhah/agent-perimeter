"use client";

/**
 * Screen 2 -- live scan (brief §7). Subscribes to the check-event stream
 * and renders checks grouped by phase (`PhaseGroup`) as they arrive, a
 * single `Skeleton` standing in for "more checks incoming" (never a
 * spinner, 00 §5.5), and one `aria-live="polite"` `role="status"` region
 * that carries the running "n of total" announcement while the scan is in
 * flight.
 *
 * That status region and the terminal summary (`EmptyState`, task-12
 * ruling 4) are rendered by the same ternary, never both at once:
 * `EmptyState` itself renders `role="status"` (`_bok-ui.tsx`), so running
 * the two together would leave two `role="status"` elements on the page
 * simultaneously -- a Playwright strict-mode violation, the same class of
 * problem Task 11 hit independently with Next's own route announcer. The
 * pending-check `Skeleton` is the other `role="status"` source (ruling 2);
 * it is gated on `hasPending`, which goes false the instant the last
 * *runnable* check's event arrives (not on the terminal frame, and not
 * simply "completed === total", since a run with a skip -- `degraded` --
 * never reaches completed === total on its own) so it clears well before
 * the terminal frame's extra pause below gives the status region a clean,
 * single-match window a Playwright poll can actually observe.
 *
 * `params`/`searchParams` are both Promises in Next 15; this page is a
 * Client Component (it does real client-side subscription work, ruling 1),
 * so they're unwrapped with React's `use()` rather than `await` --
 * `findings/page.tsx`'s `await searchParams` pattern is for an async
 * Server Component, which this can't be and still subscribe to anything.
 *
 * `?fixture=streaming|degraded|deterministic` replays a canned
 * `ScanEvent[]` (`./fixtures.ts`) through `replayScanEvents`, which shares
 * `subscribeToScanEvents`'s exact `(id, onEvent, onError?) => unsubscribe`
 * signature and dispatches on a real `setTimeout` cadence -- not one
 * synchronous dump. No live backend is reachable from this project's
 * Playwright runs (no CORS/rewrite wired), so the real `subscribeToScanEvents`
 * branch below is wired for production but isn't exercised by any test here
 * -- the same forward-reference pattern `app/page.tsx`'s real `createScan`
 * call already uses.
 */
import { use, useEffect, useMemo, useState } from "react";

import { PhaseGroup, type PhaseGroupCheck } from "@/app/components/PhaseGroup";
import { EmptyState, QuotaStrip, Skeleton, type ProviderQuota } from "@/src/lib/_bok-ui";
import { isTerminalEvent, subscribeToScanEvents, type ScanEvent, type ScanTerminalEvent } from "@/src/lib/api";
import { FIXTURES } from "./fixtures";

// 29 checks at 30ms apart (~870ms) plus a 500ms pause before the terminal
// frame -- comfortably under the ~2s ruling-2 pacing budget, and the pause
// is what gives the status region's un-collided "n of total" text a window
// wide enough for Playwright's poll interval to land inside, before it's
// swapped for the terminal summary.
const FRAME_DELAY_MS = 30;
const TERMINAL_PAUSE_MS = 500;

function replayScanEvents(
  id: string,
  events: ScanEvent[],
  onEvent: (event: ScanEvent) => void,
  _onError?: (error: Event) => void,
): () => void {
  // Kept only to match `subscribeToScanEvents`'s exact call signature
  // (ruling 1) -- a canned replay never errors, so there's nothing to call
  // it with.
  void _onError;
  let cancelled = false;
  let delay = 0;
  const timers = events.map((event) => {
    delay += isTerminalEvent(event) ? TERMINAL_PAUSE_MS : FRAME_DELAY_MS;
    return setTimeout(() => {
      if (!cancelled) onEvent(event);
    }, delay);
  });
  return () => {
    cancelled = true;
    timers.forEach(clearTimeout);
  };
}

function phaseOf(checkId: string): string {
  const dot = checkId.indexOf(".");
  return dot === -1 ? checkId : checkId.slice(0, dot);
}

interface CheckRow extends PhaseGroupCheck {
  phase: string;
}

// The only check the determinism budget lets call a model (CLAUDE.md) --
// its presence in the arrived-event stream is this screen's one signal
// that a model lane engaged at all.
const MODEL_CHECK_ID = "descriptions.llm_judge";

// ponytail: `ScanEvent` carries no real provider-quota numbers on the wire
// today -- this acknowledges the model lane engaged, it isn't live quota
// telemetry. Swap for real numbers once the backend streams them.
const PLACEHOLDER_PROVIDERS: ProviderQuota[] = [{ name: "model provider", status: "ok", used: 1, limit: 1 }];

export default function LiveScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ fixture?: string }>;
}) {
  const { id } = use(params);
  const { fixture } = use(searchParams);

  const [rows, setRows] = useState<CheckRow[]>([]);
  const [progress, setProgress] = useState<{ completed: number; total: number } | null>(null);
  const [terminalEvent, setTerminalEvent] = useState<ScanTerminalEvent | null>(null);
  const [modelEngaged, setModelEngaged] = useState(false);

  useEffect(() => {
    setRows([]);
    setProgress(null);
    setTerminalEvent(null);
    setModelEngaged(false);

    function handleEvent(event: ScanEvent) {
      if (isTerminalEvent(event)) {
        setProgress({ completed: event.completed, total: event.total });
        setTerminalEvent(event);
        if (event.skipped.length > 0) {
          setRows((prev) => [
            ...prev,
            ...event.skipped.map((s) => ({
              checkId: s.check_id,
              phase: phaseOf(s.check_id),
              status: "skipped" as const,
              detail: s.detail,
            })),
          ]);
        }
        return;
      }
      setProgress({ completed: event.completed, total: event.total });
      if (event.check_id === MODEL_CHECK_ID) setModelEngaged(true);
      setRows((prev) => [
        ...prev,
        { checkId: event.check_id, phase: event.phase, status: event.status, elapsedMs: event.elapsed_ms },
      ]);
    }

    if (fixture) {
      return replayScanEvents(id, FIXTURES[fixture] ?? [], handleEvent);
    }
    return subscribeToScanEvents(id, handleEvent);
  }, [id, fixture]);

  const phases = useMemo(() => {
    const grouped = new Map<string, PhaseGroupCheck[]>();
    for (const row of rows) {
      const list = grouped.get(row.phase) ?? [];
      list.push(row);
      grouped.set(row.phase, list);
    }
    return grouped;
  }, [rows]);

  // False once terminal fires, whatever `completed`/`total` say -- a run
  // with a skip (`degraded`) never reaches completed === total on its own,
  // and the terminal frame is the actual "nothing more is coming" signal.
  const hasPending = terminalEvent === null && (progress === null || progress.completed < progress.total);
  const skippedCount = terminalEvent?.skipped.length ?? 0;

  return (
    <main className="bok-live-scan">
      <h1>Scan {id}</h1>

      {terminalEvent === null ? (
        <p role="status" aria-live="polite" className="bok-scan-progress">
          {progress ? `${progress.completed} of ${progress.total} checks complete` : "Starting scan…"}
        </p>
      ) : (
        <EmptyState
          title="No findings for the checks that ran"
          description={
            skippedCount === 0
              ? "0 checks skipped."
              : `${skippedCount} check${skippedCount === 1 ? "" : "s"} skipped — see the skipped rows below for why.`
          }
        />
      )}

      {modelEngaged && <QuotaStrip providers={PLACEHOLDER_PROVIDERS} />}

      {[...phases.entries()].map(([phase, checks]) => (
        <PhaseGroup key={phase} phase={phase} checks={checks} />
      ))}

      {hasPending && <Skeleton lines={4} />}
    </main>
  );
}
