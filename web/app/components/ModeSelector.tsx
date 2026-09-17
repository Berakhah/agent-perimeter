"use client";

/**
 * Passive/active radio group. Active is disabled until the caller reports a
 * structurally valid scope file is attached (`activeUnlocked`) -- this
 * component never parses or validates the file itself; that's
 * `ScopeFileField`'s job (task-11 ruling 1: structural validation only, the
 * server still decides real authorisation).
 */
import type { ScanMode } from "@/src/lib/api";

export interface ModeSelectorProps {
  mode: ScanMode;
  onChange: (mode: ScanMode) => void;
  activeUnlocked: boolean;
}

// Lock copy (task-11 brief) rewritten to satisfy the RED test's
// /scope file.*authorisation/i regex -- the brief's literal copy says
// "authorising party", never the word "authorisation", so the two given
// requirements conflicted; this keeps the brief's content (target,
// authorising party, dated attestation) and states the same fact ("this is
// how the tool proves authorisation") in the word the test looks for.
const LOCK_REASON =
  "Active checks need a scope file that records authorisation: the target, the authorising party and a dated attestation.";

export function ModeSelector({ mode, onChange, activeUnlocked }: ModeSelectorProps) {
  return (
    <fieldset className="bok-mode-selector" data-unlocked={activeUnlocked}>
      <legend>Scan mode</legend>
      <label className="bok-mode-option">
        <input
          type="radio"
          name="mode"
          value="passive"
          checked={mode === "passive"}
          onChange={() => onChange("passive")}
        />
        Passive
      </label>
      <label className="bok-mode-option">
        <input
          type="radio"
          name="mode"
          value="active"
          checked={mode === "active"}
          disabled={!activeUnlocked}
          onChange={() => onChange("active")}
        />
        Active
      </label>
      {!activeUnlocked && (
        <p data-testid="active-lock-reason" className="bok-lock-reason">
          {LOCK_REASON}
        </p>
      )}
    </fieldset>
  );
}
