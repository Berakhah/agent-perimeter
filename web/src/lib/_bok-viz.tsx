"use client";

/**
 * Decorative data-visualization companions to `_bok-ui.tsx` (see that
 * file's header comment for the `bok-ui` stand-in rationale -- this is the
 * same kind of stand-in, kept in a separate file because it's a distinct,
 * decorative-only layer with no shared state or props with the rest of the
 * library). Every component here is `aria-hidden="true"`: the numbers it
 * renders already exist as accessible text elsewhere on the page (spec
 * `docs/superpowers/specs/2026-09-20-ops-console-design.md` §5).
 */

export type StatTileTone = "critical" | "high" | "medium" | "low" | "neutral";

export interface StatTile {
  label: string;
  value: number | string;
  tone?: StatTileTone;
}

export interface StatTileGridProps {
  tiles: StatTile[];
}

/** 4-across tile row (wraps below 4 on narrow viewports); tabular-mono numbers, severity-tinted accents. */
export function StatTileGrid({ tiles }: StatTileGridProps) {
  return (
    <div className="bok-stat-tile-grid" data-testid="stat-tile-grid" aria-hidden="true">
      {tiles.map((tile) => (
        <div
          key={tile.label}
          className={`bok-stat-tile bok-stat-tile-${tile.tone ?? "neutral"}`}
          data-testid={`stat-tile-${tile.label.toLowerCase()}`}
        >
          <span className="bok-stat-tile-value bok-numeric" data-testid="stat-tile-value">
            {tile.value}
          </span>
          <span className="bok-stat-tile-label">{tile.label}</span>
        </div>
      ))}
    </div>
  );
}
