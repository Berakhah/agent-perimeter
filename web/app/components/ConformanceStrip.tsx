/**
 * The findings screen's header differentiator (task-13 brief §7, spec §10
 * delta 2): "claims 2026-07-28 · observes 5 of 7 features · 2 conformance
 * gaps". Three numbers, precisely (pre-flight ruling 3):
 *
 * - claim = the scan's `revision_claimed`.
 * - observed = |`features_observed` ∩ the claimed revision's real feature
 *   bundle|; "of N" = that bundle's size.
 * - gaps = the count of findings whose `check_id` is
 *   `"revision.conformance_mismatch"` (passed in by the caller, which
 *   already has the findings list).
 *
 * `revision_claimed` absent/null renders "revision unknown", never a
 * misleading "0 of N" -- a server that claims nothing is not the same as
 * one that claims everything and delivers none of it.
 *
 * Bundle sizes are real, not the brief's illustrative "10" (ruling 2):
 * `agent_perimeter/transport/features.yaml` -- 2026-07-28 is 7 features,
 * 2025-11-25 is 4. Duplicated here rather than fetched, the same call the
 * revision-bundle-free frontend already makes for every other served
 * constant in this codebase (there is no `GET /api/revisions` endpoint).
 */
const REVISION_FEATURE_BUNDLES: Record<string, string[]> = {
  "2026-07-28": [
    "server_discover",
    "result_type",
    "cacheable_result",
    "mrtr",
    "param_headers",
    "subscriptions_listen",
    "extensions",
  ],
  "2025-11-25": ["initialize_handshake", "session_header", "sse_resumability", "subscribe_unsubscribe"],
};

export interface ConformanceStripProps {
  revisionClaimed?: string | null;
  featuresObserved?: string[];
  gapsCount: number;
}

export function ConformanceStrip({ revisionClaimed, featuresObserved = [], gapsCount }: ConformanceStripProps) {
  if (!revisionClaimed) {
    return (
      <p data-testid="conformance-strip" className="bok-conformance-strip">
        revision unknown
      </p>
    );
  }

  const bundle = REVISION_FEATURE_BUNDLES[revisionClaimed] ?? [];
  const observedSet = new Set(featuresObserved);
  const observedCount = bundle.filter((feature) => observedSet.has(feature)).length;

  return (
    <p data-testid="conformance-strip" className="bok-conformance-strip">
      claims {revisionClaimed} · observes {observedCount} of {bundle.length} features · {gapsCount} conformance
      gap{gapsCount === 1 ? "" : "s"}
    </p>
  );
}
