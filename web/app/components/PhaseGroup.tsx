/**
 * One phase's section of the live-scan check list (task-12 ruling 3):
 * `RunTimeline` is a flat chronological `<ol>` with no per-item testid, so
 * it can't be the vehicle for "checks grouped by phase, each row
 * inspectable" -- this component is. `role="group"` + `aria-labelledby`
 * pointing at the phase heading gives the section an accessible name equal
 * to the phase string (e.g. "revision"), which is what
 * `getByRole("group", { name: /revision/i })` resolves against.
 *
 * A skipped check never came through as a `ScanCheckEvent` (the backend
 * only reports skips in the terminal frame's `skipped` array -- see
 * `scan_runner.py`), but it still gets a row here with its reason spelled
 * out, never silently dropped from the list (brief: "skipped checks are
 * shown with a reason, not omitted").
 */
export interface PhaseGroupCheck {
  checkId: string;
  status: "passed" | "errored" | "skipped";
  /** Only set for a check that actually ran. */
  elapsedMs?: number;
  /** Only set for a skipped check -- the terminal frame's `skipped[].detail`. */
  detail?: string;
}

export interface PhaseGroupProps {
  phase: string;
  checks: PhaseGroupCheck[];
}

export function PhaseGroup({ phase, checks }: PhaseGroupProps) {
  const headingId = `phase-group-${phase}`;
  return (
    <section className="bok-phase-group" role="group" aria-labelledby={headingId}>
      <h2 id={headingId} className="bok-phase-group-heading">
        {phase}
      </h2>
      <ul className="bok-phase-group-list">
        {checks.map((check) => (
          <li
            key={check.checkId}
            data-testid="check-row"
            data-status={check.status}
            className={`bok-check-row bok-check-${check.status}`}
          >
            <span className="bok-numeric bok-check-id">{check.checkId}</span>
            {check.status === "skipped" ? (
              <span className="bok-check-detail">Skipped — {check.detail}</span>
            ) : (
              <span className="bok-check-detail">
                {check.status === "passed" ? "Passed" : "Errored"}
                {check.elapsedMs != null ? ` · ${check.elapsedMs}ms` : ""}
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
