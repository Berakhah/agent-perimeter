"use client";

/**
 * Screen 5 -- description-drift stub (brief §7 "v2 surface stubbed in v1";
 * task-15 pre-flight ruling). "Stubbed" means honest about being a stub: a
 * real word-level red-lined diff when two scans of the same target exist,
 * and an empty state naming exactly what's missing when they don't. Never
 * fake data, never "coming soon" (ruling 4, CLAUDE.md copy rules).
 *
 * Live data: GET /api/scans/{id}/drift (agent_perimeter/api/drift.py),
 * added by the drift-detection work (2026-09-15); before that this screen
 * had no backend and rendered the empty state unconditionally.
 * ?fixture= replays canned data so Playwright stays hermetic.
 *
 * `?fixture=single-scan|changed-description` replays canned data
 * (`./fixtures.ts`). `params`/`searchParams` are both Promises in Next 15,
 * unwrapped with `use()` (ruling 6), matching every other `[id]` route in
 * this project.
 */
import { use, useEffect, useState } from "react";

import { DiffView, EmptyState, RunTimeline, type RunTimelineEvent } from "@/src/lib/_bok-ui";
import { Sparkline } from "@/src/lib/_bok-viz";
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
    // The route stays mounted across client-side navigation between ids
    // and ?fixture= values; clear the previous fetch's result first so a
    // stale error or body cannot render against the new params.
    setLive(null);
    setError(null);
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
  // The live (non-fixture) API response carries no findings-count field
  // (`DriftResponse`/`DriftScanSummary`, src/lib/api.ts) -- `findingsCount`
  // is only ever real for fixture data. Defaulting the live path to 0 would
  // make the Sparkline draw a fabricated flat zero line for any real target
  // with two or more scans, which is exactly what its own contract forbids
  // (spec D6, "never a fabricated flat line"). `hasFindingsHistory` below
  // gates the Sparkline on this distinction.
  const hasFindingsHistory = Boolean(data);
  const scans =
    data?.scans ?? (live?.scans ?? []).map((s) => ({ id: s.id, startedAt: s.started_at, findingsCount: 0 }));
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
      {hasFindingsHistory && (
        <Sparkline
          points={scans
            .slice()
            .sort((a, b) => a.startedAt.localeCompare(b.startedAt))
            .map((s) => s.findingsCount)}
          label={`Findings per scan, ${target}`}
        />
      )}

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
