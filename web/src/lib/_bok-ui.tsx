"use client";

/**
 * Local stand-ins for `bok-ui` (00-SHARED-FOUNDATION.md §5.4).
 *
 * `bok-ui` is not published yet. This mirrors what `agent_perimeter/_contracts.py`
 * does for `bok-core`: real, minimal, correct implementations of the twelve
 * components' behavioural contract, not a full design system. When the
 * package ships, every `@/lib/_bok-ui` import becomes `@backoffice-kit/bok-ui`
 * and this file is deleted. `bok-ui` requirements raised while building this
 * stand-in (derivation-aware `Claim`, glyph-plus-label provenance columns,
 * uncalibrated-by-default `ConfidenceMeter`) are recorded in the task-10
 * brief and carried to the `backoffice-kit` session verbatim.
 *
 * Deliberately out of scope for this stand-in, each with a ponytail note at
 * its call site below: `FindingsTable` row virtualisation (small fixture/demo
 * row counts today), a full `cmdk` command palette, and Recharts-backed
 * charting for `QuotaStrip`/`RunTimeline` (both render as plain marked-up
 * lists/strips here).
 */

import {
  type KeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** bok-core requirement 1 (see `agent_perimeter/_contracts.py::Derivation`). */
export type Derivation = "schema" | "description" | "probe" | "artifact";

export type Method = "deterministic" | "model" | "human" | "derived";

export type ProvenanceState = "verified" | "modelled" | "unverified";

export type Density = "comfortable" | "compact" | "dense";

function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

const SEVERITY_META: Record<Severity, { glyph: string; label: string }> = {
  critical: { glyph: "▰▰▰▰", label: "Critical" },
  high: { glyph: "▰▰▰▱", label: "High" },
  medium: { glyph: "▰▰▱▱", label: "Medium" },
  low: { glyph: "▰▱▱▱", label: "Low" },
  info: { glyph: "▱▱▱▱", label: "Info" },
};

const DERIVATION_META: Record<Derivation, { glyph: string; label: string }> = {
  schema: { glyph: "▣", label: "Schema" },
  description: { glyph: "✎", label: "Description" },
  probe: { glyph: "◎", label: "Probe" },
  artifact: { glyph: "▤", label: "Artifact" },
};

const PROVENANCE_STATE_META: Record<ProvenanceState, { glyph: string; label: string }> = {
  verified: { glyph: "✓", label: "Verified" },
  modelled: { glyph: "≈", label: "Modelled" },
  unverified: { glyph: "?", label: "Unverified" },
};

function inferProvenanceState(method: Method): ProvenanceState {
  switch (method) {
    case "deterministic":
    case "human":
      return "verified";
    case "model":
      return "modelled";
    case "derived":
      return "unverified";
  }
}

// ---------------------------------------------------------------------------
// Claim + ProvenanceRail (00 §5.3 -- the signature element)
// ---------------------------------------------------------------------------

export interface ClaimProps {
  value: ReactNode;
  /** bok-core requirement 1: schema / description / probe / artifact, each rendered distinguishably. */
  derivation: Derivation;
  /** Applies `.bok-numeric` (tabular numerals) to the rendered value. */
  numeric?: boolean;
  /** Opens the ProvenanceRail for this claim. Omit to render a plain (non-interactive) claim. */
  onActivate?: () => void;
  className?: string;
}

/** A value that carries where it came from, underlined per 00 §5.3. */
export function Claim({ value, derivation, numeric, onActivate, className }: ClaimProps) {
  const meta = DERIVATION_META[derivation];

  const handleKeyDown = (event: KeyboardEvent<HTMLSpanElement>) => {
    if (!onActivate) return;
    const activates = event.key === "Enter" || event.key === " " || ((event.metaKey || event.ctrlKey) && event.key === ".");
    if (activates) {
      event.preventDefault();
      onActivate();
    }
  };

  return (
    <span
      className={cx("bok-claim", `bok-claim-${derivation}`, numeric && "bok-numeric", className)}
      data-testid="claim"
      data-derivation={derivation}
      data-glyph={meta.glyph}
      role={onActivate ? "button" : undefined}
      tabIndex={onActivate ? 0 : undefined}
      onClick={onActivate}
      onKeyDown={handleKeyDown}
      title={`${meta.label}-derived`}
    >
      <span aria-hidden="true" className="bok-claim-glyph">
        {meta.glyph}
      </span>
      <span className="bok-claim-value">{value}</span>
      <span className="sr-only"> ({meta.label})</span>
    </span>
  );
}

export interface ProvenanceChainEntry {
  value: ReactNode;
  method: Method;
  derivation?: Derivation;
  /** A working link, or a `file:line` reference. */
  source: string;
  sourceHref?: string;
  confidence?: number | null;
  calibrated?: boolean;
  /** ISO 8601 timestamp. */
  observedAt: string;
  caveat?: string | null;
  /** Overrides the state inferred from `method` (verified/human -> verified, model -> modelled, derived -> unverified). */
  state?: ProvenanceState;
}

export interface ProvenanceRailProps {
  open: boolean;
  /** Top to bottom: the claim itself, then its parents, nearest first. */
  chain: ProvenanceChainEntry[];
  onClose: () => void;
}

/** The right-hand evidence panel (00 §5.3). 380px, slides in, disabled under `prefers-reduced-motion`. */
export function ProvenanceRail({ open, chain, onClose }: ProvenanceRailProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  return (
    <aside
      className={cx("bok-rail", open && "bok-rail-open")}
      data-testid="provenance-rail"
      aria-hidden={!open}
      aria-label="Claim provenance"
    >
      <div className="bok-rail-header">
        <span>Provenance</span>
        <button type="button" onClick={onClose} aria-label="Close provenance rail">
          ×
        </button>
      </div>
      <ol className="bok-rail-list">
        {chain.map((entry, index) => {
          const state = entry.state ?? inferProvenanceState(entry.method);
          const stateMeta = PROVENANCE_STATE_META[state];
          return (
            <li
              key={index}
              className="bok-rail-item"
              style={{ animationDelay: open ? `${index * 30}ms` : undefined }}
            >
              <div className="bok-rail-value bok-numeric">{entry.value}</div>
              <div className="bok-rail-row">
                <span data-glyph={stateMeta.glyph} className={cx("bok-provenance-state", `bok-provenance-${state}`)}>
                  {stateMeta.glyph} {stateMeta.label}
                </span>
                {entry.derivation && (
                  <span data-glyph={DERIVATION_META[entry.derivation].glyph}>
                    {DERIVATION_META[entry.derivation].glyph} {DERIVATION_META[entry.derivation].label}
                  </span>
                )}
              </div>
              <div className="bok-rail-row">
                {entry.sourceHref ? (
                  <a href={entry.sourceHref} target="_blank" rel="noreferrer">
                    {entry.source}
                  </a>
                ) : (
                  <code>{entry.source}</code>
                )}
              </div>
              <div className="bok-rail-row bok-numeric">
                {entry.confidence != null
                  ? `${entry.calibrated ? "Calibrated" : "Uncalibrated"} confidence ${entry.confidence.toFixed(2)}`
                  : "No confidence recorded"}
              </div>
              <time className="bok-rail-row" dateTime={entry.observedAt}>
                {entry.observedAt}
              </time>
              {entry.caveat && <div className="bok-rail-caveat">{entry.caveat}</div>}
            </li>
          );
        })}
      </ol>
    </aside>
  );
}

// ---------------------------------------------------------------------------
// SeverityBadge
// ---------------------------------------------------------------------------

export interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

/** Severity is never colour-alone: glyph + label always accompany the colour (00 §5.2). */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={cx("bok-severity-badge", `bok-severity-${severity}`, className)}
      data-testid="severity-badge"
      data-glyph={meta.glyph}
      data-severity={severity}
    >
      <span aria-hidden="true">{meta.glyph}</span> {meta.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// FindingsTable
// ---------------------------------------------------------------------------

export interface FindingsTableRow {
  id: string;
  title: string;
  checkId: string;
  severity: Severity;
  derivation: Derivation;
  confidence: number | null;
}

export interface FindingsTableProps {
  rows: FindingsTableRow[];
  density?: Density;
  caption?: string;
}

const FINDINGS_COLUMNS = ["Severity", "Title", "Check", "Provenance", "Confidence"] as const;

function toCsv(rows: FindingsTableRow[]): string {
  const escape = (v: string) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const header = FINDINGS_COLUMNS.join(",");
  const lines = rows.map((r) =>
    [
      SEVERITY_META[r.severity].label,
      escape(r.title),
      r.checkId,
      // Requirement 2: CSV export must not drop the provenance column.
      DERIVATION_META[r.derivation].label,
      r.confidence != null ? r.confidence.toFixed(2) : "",
    ].join(","),
  );
  return [header, ...lines].join("\n");
}

function download(filename: string, contents: string, mime: string) {
  const blob = new Blob([contents], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Virtualised, column-resizable, keyboard-navigable, CSV/JSON export (00 §5.4).
 *
 * ponytail: no row virtualisation -- every stand-in fixture/demo dataset is
 * small enough to render in full. Swap in `@tanstack/react-virtual` (already
 * MIT-licensed, no new heavy dep) if a real scan's row count ever makes
 * that matter.
 */
export function FindingsTable({ rows, density = "compact", caption }: FindingsTableProps) {
  const [widths, setWidths] = useState<number[]>(() => FINDINGS_COLUMNS.map(() => 160));
  const dragState = useRef<{ col: number; startX: number; startWidth: number } | null>(null);
  const cellRefs = useRef<Array<Array<HTMLTableCellElement | null>>>([]);

  const onResizerDown = (col: number) => (event: ReactMouseEvent) => {
    dragState.current = { col, startX: event.clientX, startWidth: widths[col] ?? 160 };
    event.preventDefault();
  };

  useEffect(() => {
    const onMove = (event: globalThis.MouseEvent) => {
      const drag = dragState.current;
      if (!drag) return;
      const next = Math.max(60, drag.startWidth + (event.clientX - drag.startX));
      setWidths((w) => w.map((width, i) => (i === drag.col ? next : width)));
    };
    const onUp = () => {
      dragState.current = null;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  const focusCell = useCallback((row: number, col: number) => {
    const clampedRow = Math.max(0, Math.min(rows.length - 1, row));
    const clampedCol = Math.max(0, Math.min(FINDINGS_COLUMNS.length - 1, col));
    cellRefs.current[clampedRow]?.[clampedCol]?.focus();
  }, [rows.length]);

  const setCellRef = (rowIndex: number, colIndex: number) => (el: HTMLTableCellElement | null) => {
    const row = (cellRefs.current[rowIndex] ??= []);
    row[colIndex] = el;
  };

  const onCellKeyDown = (row: number, col: number) => (event: KeyboardEvent<HTMLTableCellElement>) => {
    switch (event.key) {
      case "ArrowRight":
        event.preventDefault();
        focusCell(row, col + 1);
        break;
      case "ArrowLeft":
        event.preventDefault();
        focusCell(row, col - 1);
        break;
      case "ArrowDown":
        event.preventDefault();
        focusCell(row + 1, col);
        break;
      case "ArrowUp":
        event.preventDefault();
        focusCell(row - 1, col);
        break;
    }
  };

  return (
    <div className={cx("bok-table-wrap", `bok-density-${density}`)}>
      <div className="bok-table-toolbar bok-no-print">
        <button type="button" onClick={() => download("findings.csv", toCsv(rows), "text/csv")}>
          Export CSV
        </button>
        <button type="button" onClick={() => download("findings.json", JSON.stringify(rows, null, 2), "application/json")}>
          Export JSON
        </button>
      </div>
      <table className="bok-table" data-testid="findings-table">
        {caption && <caption>{caption}</caption>}
        <colgroup>
          {FINDINGS_COLUMNS.map((_, i) => (
            <col key={i} style={{ width: widths[i] }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {FINDINGS_COLUMNS.map((col, i) => (
              <th key={col} scope="col">
                {col}
                <span
                  className="bok-col-resizer bok-no-print"
                  onMouseDown={onResizerDown(i)}
                  role="separator"
                  aria-orientation="vertical"
                  aria-label={`Resize ${col} column`}
                />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={row.id} data-testid="finding-row">
              <td
                ref={setCellRef(rowIndex, 0)}
                tabIndex={rowIndex === 0 ? 0 : -1}
                onKeyDown={onCellKeyDown(rowIndex, 0)}
              >
                <SeverityBadge severity={row.severity} />
              </td>
              <td ref={setCellRef(rowIndex, 1)} tabIndex={-1} onKeyDown={onCellKeyDown(rowIndex, 1)}>
                {row.title}
              </td>
              <td
                ref={setCellRef(rowIndex, 2)}
                tabIndex={-1}
                onKeyDown={onCellKeyDown(rowIndex, 2)}
                className="bok-numeric"
              >
                {row.checkId}
              </td>
              <td
                ref={setCellRef(rowIndex, 3)}
                tabIndex={-1}
                onKeyDown={onCellKeyDown(rowIndex, 3)}
                data-testid="provenance-cell"
                data-glyph={DERIVATION_META[row.derivation].glyph}
              >
                <span aria-hidden="true">{DERIVATION_META[row.derivation].glyph}</span>{" "}
                {DERIVATION_META[row.derivation].label}
              </td>
              <td
                ref={setCellRef(rowIndex, 4)}
                tabIndex={-1}
                onKeyDown={onCellKeyDown(rowIndex, 4)}
                data-testid="numeric-cell"
                className="bok-numeric"
              >
                {row.confidence != null ? row.confidence.toFixed(2) : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// EvidencePane
// ---------------------------------------------------------------------------

export interface EvidenceHighlight {
  start: number;
  end: number;
  label?: string;
}

export interface EvidencePaneProps {
  kind: "code" | "dom" | "document";
  content: string;
  language?: string;
  highlights?: EvidenceHighlight[];
}

/** Code/DOM/document excerpt with highlight ranges (00 §5.4). */
export function EvidencePane({ kind, content, language, highlights = [] }: EvidencePaneProps) {
  const sorted = [...highlights].sort((a, b) => a.start - b.start);
  const parts: ReactNode[] = [];
  let cursor = 0;
  sorted.forEach((h, i) => {
    if (h.start > cursor) parts.push(content.slice(cursor, h.start));
    parts.push(
      <mark key={i} title={h.label}>
        {content.slice(h.start, h.end)}
      </mark>,
    );
    cursor = h.end;
  });
  if (cursor < content.length) parts.push(content.slice(cursor));

  return (
    <pre className="bok-evidence" data-testid="evidence-pane" data-kind={kind} data-language={language}>
      <code>{parts}</code>
    </pre>
  );
}

// ---------------------------------------------------------------------------
// ConfidenceMeter
// ---------------------------------------------------------------------------

export interface ConfidenceMeterProps {
  score: number | null;
  /**
   * bok-core / 00 §B10: uncalibrated is the DEFAULT state -- the caller must
   * opt IN to "calibrated", not remember to opt out of it.
   */
  calibrated?: boolean;
  label?: string;
}

export function ConfidenceMeter({ score, calibrated = false, label }: ConfidenceMeterProps) {
  const pct = score != null ? Math.round(Math.max(0, Math.min(1, score)) * 100) : null;
  return (
    <div
      className={cx("bok-confidence-meter", !calibrated && "bok-confidence-uncalibrated")}
      data-testid="confidence-meter"
      data-calibrated={calibrated}
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct ?? undefined}
      aria-label={label ?? "Confidence"}
    >
      <div className="bok-confidence-track">
        <div className="bok-confidence-fill" style={{ width: `${pct ?? 0}%` }} />
      </div>
      <span className="bok-numeric bok-confidence-label">
        {pct != null ? `${pct}%` : "—"} · {calibrated ? "Calibrated" : "Uncalibrated"}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// QuotaStrip
// ---------------------------------------------------------------------------

export interface ProviderQuota {
  name: string;
  status: "ok" | "degraded" | "down";
  used: number;
  limit: number;
}

export interface QuotaStripProps {
  providers: ProviderQuota[];
}

const QUOTA_STATUS_META: Record<ProviderQuota["status"], { glyph: string; label: string }> = {
  ok: { glyph: "●", label: "OK" },
  degraded: { glyph: "◐", label: "Degraded" },
  down: { glyph: "○", label: "Down" },
};

/** Live provider health + quota burn (00 §5.4). */
export function QuotaStrip({ providers }: QuotaStripProps) {
  return (
    <ul className="bok-quota-strip" data-testid="quota-strip">
      {providers.map((p) => {
        const meta = QUOTA_STATUS_META[p.status];
        return (
          <li key={p.name} className={cx("bok-quota-item", `bok-quota-${p.status}`)}>
            <span aria-hidden="true" data-glyph={meta.glyph}>
              {meta.glyph}
            </span>
            <span>
              {p.name} ({meta.label})
            </span>
            <span className="bok-numeric">
              {p.used}/{p.limit}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// RunTimeline
// ---------------------------------------------------------------------------

export interface RunTimelineEvent {
  id: string;
  label: string;
  /** ISO 8601 timestamp. */
  at: string;
  status?: "ok" | "error" | "pending";
}

export interface RunTimelineProps {
  events: RunTimelineEvent[];
}

export function RunTimeline({ events }: RunTimelineProps) {
  return (
    <ol className="bok-timeline" data-testid="run-timeline">
      {events.map((e) => (
        <li key={e.id} className={cx("bok-timeline-item", e.status && `bok-timeline-${e.status}`)}>
          <time className="bok-numeric" dateTime={e.at}>
            {e.at}
          </time>
          <span>{e.label}</span>
        </li>
      ))}
    </ol>
  );
}

// ---------------------------------------------------------------------------
// DiffView
// ---------------------------------------------------------------------------

export interface DiffViewProps {
  before: string;
  after: string;
  beforeLabel?: string;
  afterLabel?: string;
}

/**
 * ponytail: naive line-set diff (added = in `after` not `before`, removed =
 * the reverse), not a real LCS/Myers alignment -- fine for a stand-in that
 * only needs to show "something changed" at a glance. Swap in the `diff`
 * npm package (MIT) for a real aligned diff if drift detection (v2) needs
 * precise line pairing.
 */
export function DiffView({ before, after, beforeLabel = "Before", afterLabel = "After" }: DiffViewProps) {
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  const beforeSet = new Set(beforeLines);
  const afterSet = new Set(afterLines);

  return (
    <div className="bok-diff" data-testid="diff-view">
      <div>
        <h3>{beforeLabel}</h3>
        {beforeLines.map((line, i) => (
          <div key={i} className={cx("bok-diff-line", !afterSet.has(line) && "bok-diff-remove")}>
            {!afterSet.has(line) ? "− " : "  "}
            {line}
          </div>
        ))}
      </div>
      <div>
        <h3>{afterLabel}</h3>
        {afterLines.map((line, i) => (
          <div key={i} className={cx("bok-diff-line", !beforeSet.has(line) && "bok-diff-add")}>
            {!beforeSet.has(line) ? "+ " : "  "}
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// EmptyState / ErrorState / Skeleton
// ---------------------------------------------------------------------------

export interface EmptyStateProps {
  title: string;
  description?: string;
}

/** Copy rules: never "You're secure!" -- callers supply the honest copy. */
export function EmptyState({ title, description }: EmptyStateProps) {
  return (
    <div className="bok-empty-state" data-testid="empty-state" role="status">
      <p className="bok-empty-title">{title}</p>
      {description && <p className="bok-empty-description">{description}</p>}
    </div>
  );
}

export interface ErrorStateProps {
  title: string;
  description?: string;
  onRetry?: () => void;
}

export function ErrorState({ title, description, onRetry }: ErrorStateProps) {
  return (
    <div className="bok-error-state" data-testid="error-state" role="alert">
      <p className="bok-error-title">{title}</p>
      {description && <p className="bok-error-description">{description}</p>}
      {onRetry && (
        <button type="button" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export interface SkeletonProps {
  lines?: number;
  className?: string;
}

/** Loading is a skeleton, never a spinner (00 §5.5). */
export function Skeleton({ lines = 3, className }: SkeletonProps) {
  return (
    <div className={cx("bok-skeleton", className)} data-testid="skeleton" role="status" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="bok-skeleton-line" />
      ))}
    </div>
  );
}
