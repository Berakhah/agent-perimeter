"use client";

/**
 * Screen 3 -- findings, headed by the revision conformance strip (brief §7;
 * spec §10 delta 2; task-13 pre-flight ruling). A Client Component, like
 * Task 12's live-scan screen, because it owns the provenance-rail
 * open/close state and the per-row expansion `FindingsTable` now supports
 * (ruling 4) -- `params`/`searchParams` are unwrapped with `use()`, the same
 * pattern that file uses for a route needing real interactivity.
 *
 * `?fixture=mismatch|unknown-revision|mixed|clean` replays canned data
 * (`./fixtures.ts`); no live backend is reachable from this project's
 * Playwright runs (ruling 5). Absent a fixture, this calls the real
 * `getFindings`/`getScan` -- wired for production, untested by this task's
 * RED suite by design.
 */
import { use, useEffect, useMemo, useState } from "react";

import { ConformanceStrip } from "@/app/components/ConformanceStrip";
import { FindingRow } from "@/app/components/FindingRow";
import {
  EmptyState,
  FindingsTable,
  ProvenanceRail,
  Skeleton,
  type EvidencePaneProps,
  type FindingsTableRow,
  type ProvenanceChainEntry,
} from "@/src/lib/_bok-ui";
import { getFindings, getScan, type Finding } from "@/src/lib/api";
import { FIXTURES, type FindingsFixture } from "./fixtures";

// EvidencePane's kind vocabulary (code/dom/document) predates the backend's
// Evidence.kind vocabulary (transcript/excerpt/screenshot/diff) -- excerpt
// and diff read as source text ("code"), a transcript reads as prose
// ("document"). ponytail: a screenshot has no text-based EvidencePane
// equivalent today, "dom" is the closest available label; give EvidencePane
// a real image-rendering kind if a screenshot finding ever needs more than
// a placeholder.
function mapEvidenceKind(kind: Finding["evidence"]["kind"]): EvidencePaneProps["kind"] {
  switch (kind) {
    case "excerpt":
    case "diff":
      return "code";
    case "transcript":
      return "document";
    case "screenshot":
      return "dom";
  }
}

function toRow(finding: Finding, index: number): FindingsTableRow {
  return {
    id: `${finding.check_id}-${index}`,
    title: finding.title,
    checkId: finding.check_id,
    severity: finding.severity,
    // claim.derivation is optional on the wire (`_contracts.py::Claim`) --
    // "artifact" is the most generic derivation, used only when a check
    // genuinely didn't record one, never fabricated as a real signal.
    derivation: finding.claim.derivation ?? "artifact",
    confidence: finding.confidence ?? finding.claim.confidence ?? null,
    cwe: finding.cwe,
    taxonomyRefs: finding.taxonomy_refs,
    reproduction: finding.reproduction,
    evidence: {
      kind: mapEvidenceKind(finding.evidence.kind),
      content: finding.evidence.excerpt,
      highlights: finding.evidence.highlight
        ? [{ start: finding.evidence.highlight[0], end: finding.evidence.highlight[1] }]
        : [],
    },
  };
}

// The wire Claim carries no explicit `source` field (pre-flight ruling 1) --
// `ProvenanceRail` needs a "working link or file:line reference" per chain
// entry, so every entry is labeled with the finding's own location
// (file:line) when known, or its check_id otherwise: the closest real
// anchor actually available, not an invented one.
function claimSource(finding: Finding): string {
  return finding.location ? `${finding.location.uri}:${finding.location.line ?? 1}` : finding.check_id;
}

function claimValueLabel(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

// Top to bottom: the claim itself, then its parents, nearest first
// (`ProvenanceRailProps.chain` doc, `_bok-ui.tsx`).
function toChain(claim: Finding["claim"], source: string): ProvenanceChainEntry[] {
  const entry: ProvenanceChainEntry = {
    value: claimValueLabel(claim.value),
    method: claim.method,
    derivation: claim.derivation ?? undefined,
    source,
    confidence: claim.confidence ?? null,
    observedAt: claim.observed_at,
    caveat: claim.caveat ?? null,
  };
  return [entry, ...(claim.parents ?? []).flatMap((parent) => toChain(parent, source))];
}

const CONFORMANCE_MISMATCH_CHECK_ID = "revision.conformance_mismatch";

export default function FindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ fixture?: string }>;
}) {
  const { id } = use(params);
  const { fixture } = use(searchParams);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [scan, setScan] = useState<FindingsFixture["scan"] | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [railOpen, setRailOpen] = useState(false);
  const [railChain, setRailChain] = useState<ProvenanceChainEntry[]>([]);

  useEffect(() => {
    let cancelled = false;
    setLoaded(false);

    if (fixture) {
      const data = FIXTURES[fixture];
      setFindings(data?.findings ?? []);
      setScan(data?.scan ?? { revisionClaimed: null, featuresObserved: [], skippedCount: 0 });
      setLoaded(true);
      return;
    }

    Promise.all([getFindings(id), getScan(id)]).then(([findingsData, scanData]) => {
      if (cancelled) return;
      setFindings(findingsData);
      setScan({
        revisionClaimed: scanData.revision_claimed ?? null,
        featuresObserved: scanData.features_observed ?? [],
        skippedCount: scanData.skipped_count ?? 0,
      });
      setLoaded(true);
    });
    return () => {
      cancelled = true;
    };
  }, [id, fixture]);

  const { rows, findingById } = useMemo(() => {
    const builtRows = findings.map(toRow);
    const map = new Map<string, Finding>();
    builtRows.forEach((row, i) => {
      const finding = findings[i];
      if (finding) map.set(row.id, finding);
    });
    return { rows: builtRows, findingById: map };
  }, [findings]);

  const gapsCount = useMemo(
    () => findings.filter((f) => f.check_id === CONFORMANCE_MISMATCH_CHECK_ID).length,
    [findings],
  );

  function handleClaimActivate(row: FindingsTableRow) {
    const finding = findingById.get(row.id);
    if (!finding) return;
    setRailChain(toChain(finding.claim, claimSource(finding)));
    setRailOpen(true);
  }

  if (!loaded) {
    return (
      <main className="bok-findings">
        <Skeleton lines={6} />
      </main>
    );
  }

  const skippedCount = scan?.skippedCount ?? 0;

  return (
    <main className="bok-findings">
      <h1>Findings</h1>
      <ConformanceStrip
        revisionClaimed={scan?.revisionClaimed}
        featuresObserved={scan?.featuresObserved}
        gapsCount={gapsCount}
      />

      {rows.length === 0 ? (
        <EmptyState
          title="No findings for the checks that ran"
          description={`${skippedCount} skipped — see the scan's skip reasons for details.`}
        />
      ) : (
        <FindingsTable
          rows={rows}
          caption={`Findings for scan ${id}`}
          onClaimActivate={handleClaimActivate}
          renderExpanded={(row) => <FindingRow reproduction={row.reproduction ?? ""} evidence={row.evidence} />}
        />
      )}

      <ProvenanceRail open={railOpen} chain={railChain} onClose={() => setRailOpen(false)} />
    </main>
  );
}
