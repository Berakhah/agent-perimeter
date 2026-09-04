"use client";

/**
 * Screen 1 -- scan setup (brief §7). The one thing that must be exactly
 * right: active mode is disabled and visibly locked until a structurally
 * valid scope file is attached, and the lock explains why in one sentence
 * (`ModeSelector`). Target is the page's first focusable element -- there's
 * no header/nav above it (`app/layout.tsx`) -- so it's also the form's
 * natural first Tab stop.
 *
 * Submitting calls the real API (`createScan`) and navigates to
 * `/scans/{id}` on success; `/scans/{id}` doesn't exist yet (a later task),
 * same as any other forward reference in this codebase. A thrown `ApiError`
 * renders through `ErrorState` rather than being swallowed.
 */
import { type FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

import { ErrorState } from "@/src/lib/_bok-ui";
import { ApiError, createScan, type ScanMode, type ScopeFileInput } from "@/src/lib/api";
import { ModeSelector } from "./components/ModeSelector";
import { ScopeFileField } from "./components/ScopeFileField";

export default function Home() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("passive");
  const [scopeFile, setScopeFile] = useState<ScopeFileInput | null>(null);
  const [scopeFileError, setScopeFileError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function handleScopeFile(next: ScopeFileInput | null) {
    setScopeFile(next);
    // The active radio is about to become disabled again; don't leave the
    // form silently holding a mode its own UI no longer offers.
    if (!next && mode === "active") setMode("passive");
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitError(null);
    setSubmitting(true);
    try {
      const accepted = await createScan({
        target,
        mode,
        scope_file: mode === "active" && scopeFile ? scopeFile : undefined,
      });
      router.push(`/scans/${accepted.id}`);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? `The scan API returned ${err.status} — check the target and try again.`
          : "Could not reach the scan API — confirm it is running and retry.";
      setSubmitError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="bok-scan-setup">
      <h1>Agent Perimeter</h1>
      <p>Security posture scanner for MCP servers and tool-using agents.</p>

      <form onSubmit={handleSubmit}>
        <div className="bok-field">
          <label htmlFor="target">Target</label>
          <input
            id="target"
            name="target"
            type="text"
            required
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="stdio command, https:// URL, or registry reference"
          />
        </div>

        <ScopeFileField onScopeFile={handleScopeFile} onError={setScopeFileError} />
        {scopeFileError && <ErrorState title="Scope file incomplete" description={scopeFileError} />}

        <ModeSelector mode={mode} onChange={setMode} activeUnlocked={scopeFile !== null} />

        {submitError && (
          <ErrorState
            title="Scan could not be started"
            description={submitError}
            onRetry={() => setSubmitError(null)}
          />
        )}

        <button type="submit" disabled={submitting || target.trim() === ""}>
          {submitting ? "Starting scan…" : "Start scan"}
        </button>
      </form>
    </main>
  );
}
