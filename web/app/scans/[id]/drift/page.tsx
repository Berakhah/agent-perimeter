"use client";

/**
 * Screen 5 -- description-drift stub (brief §7 "v2 surface stubbed in v1";
 * task-15 pre-flight ruling). "Stubbed" means honest about being a stub: a
 * real word-level red-lined diff when two scans of the same target exist,
 * and an empty state naming exactly what's missing when they don't. Never
 * fake data, never "coming soon" (ruling 4, CLAUDE.md copy rules).
 *
 * Ruling 1 -- the one genuine difference from every prior screen's ruling:
 * there is no live backend for this screen at all. `Tool.description_hash`
 * and `DriftEvent` are real DB columns, but no route in this project's
 * final API surface (Task 9's route list) ever reads scan history or drift
 * events back over HTTP, and no later task adds one. So unlike Screens 1-4
 * ("wired for real, just untested by this task's RED suite"), the
 * `!fixture` branch below isn't a forward reference to a real fetch -- it's
 * the same honest "not enough scan history" empty state, unconditionally,
 * because there's no backend capability yet to determine otherwise. A real
 * scan-history/drift endpoint is a bigger, separate decision for the human
 * partner (ruling 1) and is explicitly out of scope for this task.
 *
 * `?fixture=single-scan|changed-description` replays canned data
 * (`./fixtures.ts`). `params`/`searchParams` are both Promises in Next 15,
 * unwrapped with `use()` (ruling 6), matching every other `[id]` route in
 * this project.
 */
import { use } from "react";

import { DiffView, EmptyState, RunTimeline, type RunTimelineEvent } from "@/src/lib/_bok-ui";
import { FIXTURES } from "./fixtures";

export default function DriftPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ fixture?: string }>;
}) {
  const { id } = use(params);
  const { fixture } = use(searchParams);

  const data = fixture ? FIXTURES[fixture] : undefined;
  const scans = data?.scans ?? [];
  const driftedTools = data?.driftedTools ?? [];

  if (scans.length < 2) {
    return (
      <main className="bok-drift">
        <h1>Description drift — scan {id}</h1>
        <EmptyState
          title="Not enough scan history yet"
          description={`This target has ${scans.length} scan${scans.length === 1 ? "" : "s"} on record — needs at least two scans of the same target before a description change can be detected.`}
        />
      </main>
    );
  }

  const timelineEvents: RunTimelineEvent[] = scans
    .slice()
    .sort((a, b) => a.startedAt.localeCompare(b.startedAt))
    .map((scan) => ({ id: scan.id, label: `Scan of ${data!.target}`, at: scan.startedAt }));

  return (
    <main className="bok-drift">
      <h1>Description drift — scan {id}</h1>
      <RunTimeline events={timelineEvents} />

      {driftedTools.length === 0 ? (
        <EmptyState
          title="No description drift detected"
          description={`${scans.length} scans compared — no tool description changed between them.`}
        />
      ) : (
        driftedTools.map((tool) => (
          <section key={tool.id} aria-labelledby={`drift-${tool.id}`}>
            <h2 id={`drift-${tool.id}`}>{tool.name}</h2>
            <p>
              {tool.driftEvent.field} changed, severity {tool.driftEvent.severity}, detected{" "}
              {tool.driftEvent.detected_at}
            </p>
            <DiffView before={tool.descriptionBefore} after={tool.descriptionAfter} granularity="word" />
          </section>
        ))
      )}
    </main>
  );
}
