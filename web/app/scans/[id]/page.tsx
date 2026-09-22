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
 * synchronous dump. `tests/live-scan.spec.ts`'s route-mocked real-path test
 * is the one test that exercises the real (non-fixture) branch below at
 * all; `onError` surfaced through `ErrorState`, `onRetry` bumping
 * `retryCount` to re-run the subscription effect, is still untested -- the
 * same forward-reference pattern `app/page.tsx`'s real `createScan` call
 * already uses.
 *
 * Terminal-summary fix (final-review fix wave, Important #2): the terminal
 * frame alone never means "no findings" -- it only means "no more checks
 * are running". The real (non-fixture) path fetches `getScan(id)` once the
 * terminal frame arrives and branches on `findings_count`: zero renders the
 * existing `EmptyState` copy unchanged, a positive count states the number
 * and points at the findings link above (never invented reassurance), and
 * an absent/failed count reads as "unknown", never as a false zero -- see
 * `findingsCount`'s state comment below. None of the three fixture
 * scenarios represents an unclean run, so fixture mode is untouched.
 */
import { use, useEffect, useMemo, useState, type ReactNode } from "react";

import { motion } from "motion/react";

import { PhaseGroup, type PhaseGroupCheck } from "@/app/components/PhaseGroup";
import { EmptyState, ErrorState, QuotaStrip, Skeleton, type ProviderQuota } from "@/src/lib/_bok-ui";
import { StatTileGrid } from "@/src/lib/_bok-viz";
import { getScan, isTerminalEvent, subscribeToScanEvents, type ScanEvent, type ScanTerminalEvent } from "@/src/lib/api";
import { useFadeIn } from "@/src/lib/motion";
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
// telemetry, and is gated on `fixture` (below) so it only ever appears in a
// fixture demo, never as fabricated data in a real scan. Swap for real
// numbers, unconditionally rendered, once the backend streams them.
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
  const [connectionError, setConnectionError] = useState(false);
  // Bumping this re-runs the subscription effect -- `onRetry` below's way of
  // re-opening the real EventSource after a connection error (fixture mode
  // never errors, so this is only ever touched on the real path).
  const [retryCount, setRetryCount] = useState(0);
  // Real path only (fixture mode never sets this -- see the terminal-summary
  // ternary below). `undefined` covers both "not fetched yet" and "fetched
  // but the field/fetch came back empty" -- both read as "unknown", never as
  // a false zero, the same absence-reads-as-unknown convention
  // `ConformanceStrip`'s `revisionClaimed` handling already established.
  const [findingsCount, setFindingsCount] = useState<number | undefined>(undefined);

  useEffect(() => {
    setRows([]);
    setProgress(null);
    setTerminalEvent(null);
    setModelEngaged(false);
    setConnectionError(false);
    setFindingsCount(undefined);

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
        // Fixture replays carry no backing `getScan` to call -- the real
        // scan's completion is the only case where the true findings count
        // needs fetching at all.
        if (!fixture) {
          getScan(id)
            .then((status) => setFindingsCount(status.findings_count))
            .catch(() => setFindingsCount(undefined));
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
    return subscribeToScanEvents(id, handleEvent, () => setConnectionError(true));
  }, [id, fixture, retryCount]);

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
  const passedCount = rows.filter((r) => r.status === "passed").length;
  const coverage =
    progress && progress.total > 0 ? `${Math.round((passedCount / progress.total) * 100)}%` : "—";

  return (
    <main className="bok-live-scan">
      <h1>Scan {id}</h1>
      {/* Always present, from the first paint -- unlike the streamed check
          rows below (nothing renders until the first event arrives, tens of
          milliseconds after load at best), this is real, deterministic
          navigation to the scan's own findings screen, not invented chrome.
          tests/a11y.spec.ts's single-Tab-press keyboard/focus-ring checks
          run immediately after `goto`, before any streamed content exists. */}
      <p>
        <a href={`/scans/${id}/findings`} data-testid="findings-link">
          View findings for this scan
        </a>
      </p>

      {terminalEvent === null ? (
        <p role="status" aria-live="polite" className="bok-scan-progress">
          {progress ? `${progress.completed} of ${progress.total} checks complete` : "Starting scan…"}
        </p>
      ) : (
        <TerminalFrame>
          {fixture || findingsCount === 0 ? (
            // Fixture mode: none of the three canned scenarios represents an
            // unclean run, so this stays the existing, verified-clean copy.
            // Real mode: `findingsCount === 0` is the one case where "No
            // findings" is actually true.
            <EmptyState
              title="No findings for the checks that ran"
              description={
                skippedCount === 0
                  ? "0 checks skipped."
                  : `${skippedCount} check${skippedCount === 1 ? "" : "s"} skipped — see the skipped rows below for why.`
              }
            />
          ) : typeof findingsCount === "number" ? (
            <p data-testid="findings-summary" role="status" aria-live="polite">
              {findingsCount} finding{findingsCount === 1 ? "" : "s"} — see the findings link above.
            </p>
          ) : (
            // `getScan` hasn't resolved yet, or it failed -- absence is not the
            // same claim as zero, so this never falls back to "No findings".
            <p data-testid="findings-summary" role="status" aria-live="polite">
              findings count unknown — see the findings link above to check.
            </p>
          )}
        </TerminalFrame>
      )}

      <StatTileGrid
        tiles={[
          { label: "Findings", value: typeof findingsCount === "number" ? findingsCount : "—" },
          { label: "Passed", value: passedCount },
          { label: "Skipped", value: skippedCount, tone: skippedCount > 0 ? "medium" : "neutral" },
          { label: "Coverage", value: coverage },
        ]}
      />

      {connectionError && (
        <ErrorState
          title="Lost connection to the scan"
          description="The live update stream disconnected — retry to reconnect."
          onRetry={() => setRetryCount((n) => n + 1)}
        />
      )}

      {/* Fixture-gated (not just `modelEngaged`): `ScanEvent` carries no real
          quota telemetry, so a real scan must never show invented numbers. */}
      {modelEngaged && fixture && <QuotaStrip providers={PLACEHOLDER_PROVIDERS} />}

      {[...phases.entries()].map(([phase, checks]) => (
        <PhaseGroup key={phase} phase={phase} checks={checks} />
      ))}

      {hasPending && <Skeleton lines={4} />}
    </main>
  );
}

/**
 * Fades in whichever terminal element replaces the running progress
 * announcer (spec §4.2). A wrapper `div`, not a `motion.p`, so the three
 * terminal branches above keep their own role="status" elements untouched.
 * Mounting this is the same render that unmounts `.bok-scan-progress`, so
 * there is never a moment with two live regions.
 */
function TerminalFrame({ children }: { children: ReactNode }) {
  const fade = useFadeIn();
  return (
    <motion.div {...fade} data-testid="terminal-frame">
      {children}
    </motion.div>
  );
}
