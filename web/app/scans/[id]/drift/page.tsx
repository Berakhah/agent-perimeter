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
 * Live data: GET /api/scans/{id}/drift (agent_perimeter/api/drift.py).
 * ?fixture= replays canned data so Playwright stays hermetic.
 *
 * `?fixture=single-scan|changed-description` replays canned data
 * (`./fixtures.ts`). `params`/`searchParams` are both Promises in Next 15,
 * unwrapped with `use()` (ruling 6), matching every other `[id]` route in
 * this project.
 */
import { use, useEffect, useState } from "react";

import { DiffView, EmptyState, RunTimeline, type RunTimelineEvent } from "@/src/lib/_bok-ui";
import { getDrift, type DriftResponse } from "@/src/lib/api";
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

  const [live, setLive] = useState<DriftResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (fixture) return;
    let cancelled = false;
    getDrift(id)
      .then((body) => {
        if (!cancelled) setLive(body);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [id, fixture]);

  const data = fixture ? FIXTURES[fixture] : undefined;
  const target = data?.target ?? live?.target_ref ?? "";
  const scans = data?.scans ?? (live?.scans ?? []).map((s) => ({ id: s.id, startedAt: s.started_at }));
  const driftedTools =
    data?.driftedTools ??
    (live?.drifted_tools ?? []).map((t) => ({
      id: `${t.name}-${t.field}`,
      name: t.name,
      descriptionBefore: t.old_text ?? "",
      descriptionAfter: t.new_text ?? "",
      driftEvent: {
        id: `${t.name}-${t.field}`,
        tool_id: "",
        field: t.field,
        old_hash: t.old_hash ?? "",
        new_hash: t.new_hash ?? "",
        detected_at: "",
        severity: t.severity,
      },
    }));

  if (error) {
    return (
      <main className="bok-drift">
        <h1>Description drift — scan {id}</h1>
        <EmptyState title="Could not load drift history" description={error} />
      </main>
    );
  }

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
    .map((scan) => ({
      id: scan.id,
      label: `Scan of ${target}`,
      at: scan.startedAt,
      href: `/scans/${scan.id}`,
    }));

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
              {tool.driftEvent.field} changed, severity {tool.driftEvent.severity}
            </p>
            <DiffView before={tool.descriptionBefore} after={tool.descriptionAfter} granularity="word" />
          </section>
        ))
      )}
    </main>
  );
}
