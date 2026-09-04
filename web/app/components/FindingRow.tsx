"use client";

/**
 * A finding row's expansion content: the reproduction command (with a copy
 * button) plus its evidence excerpt. Kept out of `_bok-ui.tsx` (task-13
 * pre-flight ruling 4) -- "reproduction command" is a domain concept of this
 * scanner, not something a generic findings-table component should know
 * about. Passed into `FindingsTable` via its `renderExpanded` slot.
 */
import { useState } from "react";

import { EvidencePane, type EvidencePaneProps } from "@/src/lib/_bok-ui";

export interface FindingRowProps {
  reproduction: string;
  evidence?: EvidencePaneProps;
}

export function FindingRow({ reproduction, evidence }: FindingRowProps) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="bok-finding-expanded">
      <div className="bok-finding-reproduction">
        <pre data-testid="reproduction">{reproduction}</pre>
        <button
          type="button"
          onClick={() => {
            // Clipboard access can be denied by the browser/context (no
            // permission granted, insecure origin) -- that must not break
            // the button itself, just leave "copied" unset.
            navigator.clipboard?.writeText(reproduction).then(
              () => setCopied(true),
              () => {},
            );
          }}
        >
          {copied ? "Copied" : "Copy reproduction command"}
        </button>
      </div>
      {evidence && <EvidencePane {...evidence} />}
    </div>
  );
}
