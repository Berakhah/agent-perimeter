"use client";

/**
 * Screen 4 -- the capability graph (brief §7, "the signature moment, the
 * screen the deck leads with"; task-14 pre-flight ruling). A Client
 * Component, same reason as Tasks 12/13: it owns the ProvenanceRail
 * open/close state a static Server Component can't. `params`/`searchParams`
 * are both Promises in Next 15, unwrapped with `use()` (ruling 7).
 *
 * `?fixture=deputy|mixed-derivation|no-tools` replays canned data
 * (`./fixtures.ts`); no live backend is reachable from this project's
 * Playwright runs (ruling 6). Absent a fixture, this calls the real
 * `getGraph`/`getFindings` and cross-references policy-flagged tools from
 * the findings list -- wired for production, untested by this task's RED
 * suite by design.
 */
import { use, useEffect, useState } from "react";

import { CapabilityGraph } from "@/app/components/CapabilityGraph";
import { EmptyState, ProvenanceRail, Skeleton, type ProvenanceChainEntry } from "@/src/lib/_bok-ui";
import { getFindings, getGraph, type CapabilityEdge, type FindingClaim } from "@/src/lib/api";
import { FIXTURES } from "./fixtures";

// Pre-flight ruling 1: "policy-flagged" is not a field on the wire edge --
// it's cross-referenced from real findings whose check_id starts with
// "policy." (policy.confused_deputy / policy.secret_egress,
// `agent_perimeter/graph/policy.py`), the same check_id-prefix pattern
// `ConformanceStrip` (task 13) already used for its gaps count. A policy
// finding's `claim.value` is the flagged tool's own name
// (`graph/policy.py::evaluate()`: `claim=Claim(value=tool, ...)`).
const POLICY_CHECK_PREFIX = "policy.";

function claimValueLabel(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

// Nearest-first: the capability claim itself, then any recorded parents --
// the same flattening `findings/page.tsx`'s `toChain` uses (task-13
// pattern), applied per capability edge rather than per finding.
function flattenClaim(claim: FindingClaim, source: string): ProvenanceChainEntry[] {
  return [
    {
      value: claimValueLabel(claim.value),
      method: claim.method,
      derivation: claim.derivation ?? undefined,
      source,
      confidence: claim.confidence ?? null,
      observedAt: claim.observed_at,
      caveat: claim.caveat ?? null,
    },
    ...(claim.parents ?? []).flatMap((parent) => flattenClaim(parent, source)),
  ];
}

function chainForTool(edges: CapabilityEdge[], tool: string): ProvenanceChainEntry[] {
  return edges.filter((edge) => edge.tool === tool).flatMap((edge) => flattenClaim(edge.claim, edge.rationale));
}

export default function GraphPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ fixture?: string }>;
}) {
  const { id } = use(params);
  const { fixture } = use(searchParams);

  // Fixture data is a module-level constant, already resolved by the time
  // this renders -- computed directly in the render body (not behind a
  // `useEffect`) so a fixture run's first paint already carries the real
  // graph, with no Skeleton-then-content flash. `tests/graph.spec.ts`'s
  // keyboard test presses Tab exactly once, immediately after `goto`, with
  // no wait for content -- an effect-deferred fixture load would still be
  // showing the loading Skeleton (no focusable nodes) at that instant.
  const fixtureData = fixture ? FIXTURES[fixture] : undefined;

  const [liveEdges, setLiveEdges] = useState<CapabilityEdge[]>([]);
  const [liveFlaggedTools, setLiveFlaggedTools] = useState<Set<string>>(new Set());
  const [liveLoaded, setLiveLoaded] = useState(false);
  const [railOpen, setRailOpen] = useState(false);
  const [railChain, setRailChain] = useState<ProvenanceChainEntry[]>([]);

  useEffect(() => {
    if (fixture) return;
    let cancelled = false;
    setLiveLoaded(false);

    Promise.all([getGraph(id), getFindings(id)]).then(([graphData, findingsData]) => {
      if (cancelled) return;
      setLiveEdges(graphData);
      const flagged = new Set<string>();
      for (const finding of findingsData) {
        if (finding.check_id.startsWith(POLICY_CHECK_PREFIX) && typeof finding.claim.value === "string") {
          flagged.add(finding.claim.value);
        }
      }
      setLiveFlaggedTools(flagged);
      setLiveLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  }, [id, fixture]);

  // Gated on `fixture` (the param itself), not `fixtureData` -- an unknown
  // fixture name must still render (as an empty graph), not hang on the
  // Skeleton forever waiting for a `useEffect` that returns early.
  const edges = fixture ? (fixtureData?.edges ?? []) : liveEdges;
  const flaggedTools = fixture ? new Set(fixtureData?.flaggedTools ?? []) : liveFlaggedTools;
  const loaded = fixture ? true : liveLoaded;

  function handleActivateTool(tool: string) {
    setRailChain(chainForTool(edges, tool));
    setRailOpen(true);
  }

  if (!loaded) {
    return (
      <main className="bok-graph-page">
        <Skeleton lines={6} />
      </main>
    );
  }

  return (
    <main className="bok-graph-page">
      <h1>Capability graph</h1>
      {edges.length === 0 ? (
        <EmptyState
          title="No tools were enumerated"
          description="The scan produced no capability edges to graph — see the findings screen for why."
        />
      ) : (
        <CapabilityGraph edges={edges} flaggedTools={flaggedTools} onActivateTool={handleActivateTool} />
      )}
      <ProvenanceRail open={railOpen} chain={railChain} onClose={() => setRailOpen(false)} />
    </main>
  );
}
