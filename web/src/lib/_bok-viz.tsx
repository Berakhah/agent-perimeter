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

export interface SparklineProps {
  points: number[];
  label: string;
}

const SPARKLINE_WIDTH = 120;
const SPARKLINE_HEIGHT = 28;

/** Thin amber polyline over recent finding counts. Renders nothing for fewer than 2 points -- never a fabricated flat line (spec D6). */
export function Sparkline({ points, label }: SparklineProps) {
  if (points.length < 2) return null;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const coords = points
    .map((value, i) => {
      const x = (i / (points.length - 1)) * SPARKLINE_WIDTH;
      const y = SPARKLINE_HEIGHT - ((value - min) / range) * SPARKLINE_HEIGHT;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      className="bok-sparkline"
      data-testid="findings-sparkline"
      aria-hidden="true"
      viewBox={`0 0 ${SPARKLINE_WIDTH} ${SPARKLINE_HEIGHT}`}
      role="img"
    >
      <title>{label}</title>
      <polyline points={coords} fill="none" stroke="var(--accent)" strokeWidth="1.5" />
    </svg>
  );
}
