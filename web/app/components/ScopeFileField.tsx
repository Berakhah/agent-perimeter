"use client";

/**
 * File input (plus a drag-drop dropzone around it) for the scope file that
 * unlocks active mode. Reads and JSON.parses the file, then checks for the
 * three fields `ScopeFileInput` requires -- `target`, `authorising_party`,
 * `attestation`, in that order -- and reports the first missing/blank one.
 *
 * This is structural validation only (task-11 ruling 1): it never decides
 * whether the scope file actually authorises the target. A structurally
 * valid file is handed up as a typed `ScopeFileInput`; the server renders
 * the real authorisation answer when the scan is submitted.
 */
import { type ChangeEvent, type DragEvent, useState } from "react";

import type { ScopeFileInput } from "@/src/lib/api";

export interface ScopeFileFieldProps {
  onScopeFile: (scopeFile: ScopeFileInput | null) => void;
  onError: (message: string | null) => void;
}

const REQUIRED_FIELDS: Array<{ key: keyof ScopeFileInput; label: string }> = [
  { key: "target", label: "target" },
  { key: "authorising_party", label: "authorising party" },
  { key: "attestation", label: "attestation" },
];

function isBlank(value: unknown): boolean {
  return typeof value !== "string" || value.trim() === "";
}

export function ScopeFileField({ onScopeFile, onError }: ScopeFileFieldProps) {
  const [fileName, setFileName] = useState<string | null>(null);

  async function processFile(file: File) {
    setFileName(file.name);

    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      onScopeFile(null);
      onError(`${file.name} is not valid JSON — attach a valid JSON scope file.`);
      return;
    }
    if (typeof parsed !== "object" || parsed === null) {
      onScopeFile(null);
      onError(`${file.name} must contain a JSON object — attach a valid JSON scope file.`);
      return;
    }

    const record = parsed as Record<string, unknown>;
    const missing = REQUIRED_FIELDS.find(({ key }) => isBlank(record[key]));
    if (missing) {
      onScopeFile(null);
      onError(`Scope file is missing ${missing.label} — add it and reattach the file.`);
      return;
    }

    onScopeFile(record as unknown as ScopeFileInput);
    onError(null);
  }

  function handleInputChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) void processFile(file);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const file = event.dataTransfer.files?.[0];
    if (file) void processFile(file);
  }

  return (
    <div className="bok-scope-file-field" onDragOver={(e) => e.preventDefault()} onDrop={handleDrop}>
      <label htmlFor="scope-file">Scope file</label>
      <input
        id="scope-file"
        data-testid="scope-file"
        type="file"
        accept="application/json,.json"
        onChange={handleInputChange}
      />
      <p className="bok-hint">
        Drop or choose the scope file naming the target, the authorising party and a dated attestation.
      </p>
      {fileName && <p className="bok-scope-file-name">{fileName}</p>}
    </div>
  );
}
