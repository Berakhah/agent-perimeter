"use client";

/**
 * Fixture-only demo of `Claim` opening `ProvenanceRail` -- exercises the
 * activation/focus-management contract end to end so it's covered by a real
 * page, not just unit-level reasoning. Task 11's real findings screen wires
 * a `Claim` like this one around each finding's confidence value; this is
 * the minimal wiring needed to prove the contract works, not that screen.
 */
import { useState } from "react";

import { Claim, ProvenanceRail, type ProvenanceChainEntry } from "@/src/lib/_bok-ui";

const DEMO_CHAIN: ProvenanceChainEntry[] = [
  {
    value: "0.95",
    method: "deterministic",
    derivation: "probe",
    source: "agent_perimeter/checks/active/path_traversal.py:42",
    confidence: 0.95,
    calibrated: false,
    observedAt: "2026-09-04T10:00:00Z",
  },
];

export function ProvenanceDemo() {
  const [open, setOpen] = useState(false);
  return (
    <section>
      <h2>Provenance</h2>
      <p>
        Confidence: <Claim value="0.95" derivation="probe" numeric onActivate={() => setOpen(true)} />
      </p>
      <ProvenanceRail open={open} chain={DEMO_CHAIN} onClose={() => setOpen(false)} />
    </section>
  );
}
