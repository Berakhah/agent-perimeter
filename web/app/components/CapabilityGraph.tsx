"use client";

/**
 * Screen 4's canvas: a bipartite tool <-> capability graph (brief §7,
 * task-14 pre-flight ruling 1) plus the always-in-DOM accessible table that
 * is the graph's honest text alternative. Both are built from one shared,
 * ordered `edges` list -- tool tab order follows each tool's first
 * appearance in that list, the same order the table's rows render in
 * (ruling 3) -- so the two views cannot drift apart.
 *
 * ponytail: node positions come from a static two-column layout (tools
 * left, the 7 fixed capabilities right), not a real force simulation. No
 * requirement or test here needs organic clustering at this bounded node
 * count; swap in a force-layout pass (or a library) if a future task wants
 * one for a much larger graph.
 */
import { useLayoutEffect, useMemo, useState, type KeyboardEvent } from "react";

import { DERIVATION_META, type Derivation } from "@/src/lib/_bok-ui";
import type { Capability, CapabilityEdge } from "@/src/lib/api";
import { EdgeTooltip } from "./EdgeTooltip";

const CAPABILITY_ORDER: Capability[] = [
  "fs_read",
  "fs_write",
  "net_out",
  "exec",
  "secret_read",
  "db_read",
  "db_write",
];

const CAPABILITY_LABEL: Record<Capability, string> = {
  fs_read: "Filesystem read",
  fs_write: "Filesystem write",
  net_out: "Network egress",
  exec: "Exec",
  secret_read: "Secret read",
  db_read: "Database read",
  db_write: "Database write",
};

const DERIVATIONS: Derivation[] = ["schema", "name", "description", "probe", "artifact"];

// Derivation maps to stroke pattern AND a legend entry, never colour alone
// (00 §5.2, task-14 pre-flight ruling 4) -- every value distinguishable
// from every other, `probe` vs `description` specifically (tests/graph.spec.ts).
const DASH_ARRAY: Record<Derivation, string> = {
  schema: "1 0",
  name: "2 2",
  description: "6 3",
  probe: "1 4",
  artifact: "9 2 2 2",
};

const TOOL_X = 110;
const CAP_X = 370;
const ROW_H = 48;
const TOP_PAD = 32;
const VIEW_W = 520;

function activates(event: KeyboardEvent) {
  return event.key === "Enter" || event.key === " ";
}

export interface CapabilityGraphProps {
  edges: CapabilityEdge[];
  flaggedTools: ReadonlySet<string>;
  onActivateTool: (tool: string) => void;
}

export function CapabilityGraph({ edges, flaggedTools, onActivateTool }: CapabilityGraphProps) {
  // One shared ordered list drives both the table (rows below, in this
  // order) and the graph's tool tab order (ruling 3).
  const toolOrder = useMemo(() => {
    const seen: string[] = [];
    for (const edge of edges) if (!seen.includes(edge.tool)) seen.push(edge.tool);
    return seen;
  }, [edges]);

  const toolY = useMemo(() => {
    const map = new Map<string, number>();
    toolOrder.forEach((tool, i) => map.set(tool, TOP_PAD + i * ROW_H));
    return map;
  }, [toolOrder]);

  const capY = useMemo(() => {
    const map = new Map<Capability, number>();
    CAPABILITY_ORDER.forEach((cap, i) => map.set(cap, TOP_PAD + i * ROW_H));
    return map;
  }, []);

  const height = TOP_PAD * 2 + Math.max(toolOrder.length, CAPABILITY_ORDER.length) * ROW_H;

  const [activeEdge, setActiveEdge] = useState<CapabilityEdge | null>(null);

  return (
    <div className="bok-graph">
      {/* No `role="img"` here -- this SVG has real interactive descendants
          (focusable tool nodes and edges), and `role="img"` would tell
          assistive tech to flatten them into a single opaque image, the
          opposite of what "fully navigable from the keyboard" needs. */}
      <svg
        className="bok-graph-canvas"
        viewBox={`0 0 ${VIEW_W} ${height}`}
        aria-label="Capability graph: tools on the left, capabilities on the right"
      >
        {toolOrder.map((tool) => (
          <ToolNode
            key={tool}
            tool={tool}
            x={TOOL_X}
            y={toolY.get(tool) ?? TOP_PAD}
            flagged={flaggedTools.has(tool)}
            onActivate={() => onActivateTool(tool)}
          />
        ))}

        {CAPABILITY_ORDER.map((cap) => (
          <g
            key={cap}
            transform={`translate(${CAP_X}, ${capY.get(cap) ?? TOP_PAD})`}
            className="bok-graph-node-capability"
          >
            <circle r={12} />
            <text x={20} dy="0.35em">
              {CAPABILITY_LABEL[cap]}
            </text>
          </g>
        ))}

        {/* Rendered last so tool nodes above stay first in tab order
            (tests/graph.spec.ts "the graph is fully navigable from the
            keyboard" -- a single Tab press must land on the first node). */}
        {edges.map((edge, i) => {
          const y1 = toolY.get(edge.tool) ?? TOP_PAD;
          const y2 = capY.get(edge.capability) ?? TOP_PAD;
          return (
            <line
              key={`${edge.tool}-${edge.capability}-${i}`}
              data-testid="edge"
              data-derivation={edge.derivation}
              className="bok-graph-edge"
              x1={TOOL_X}
              y1={y1}
              x2={CAP_X}
              y2={y2}
              strokeDasharray={DASH_ARRAY[edge.derivation]}
              tabIndex={0}
              aria-label={`${edge.tool} has ${CAPABILITY_LABEL[edge.capability]}, ${DERIVATION_META[edge.derivation].label}-derived: ${edge.rationale}`}
              onMouseEnter={() => setActiveEdge(edge)}
              onMouseLeave={() => setActiveEdge((current) => (current === edge ? null : current))}
              onFocus={() => setActiveEdge(edge)}
              onBlur={() => setActiveEdge((current) => (current === edge ? null : current))}
            >
              <title>{`${DERIVATION_META[edge.derivation].label}: ${edge.rationale}`}</title>
            </line>
          );
        })}
      </svg>

      {activeEdge && (
        <EdgeTooltip
          tool={activeEdge.tool}
          capability={CAPABILITY_LABEL[activeEdge.capability]}
          derivation={activeEdge.derivation}
          rationale={activeEdge.rationale}
        />
      )}

      <ul className="bok-graph-legend" aria-label="Edge derivation legend">
        {DERIVATIONS.map((d) => (
          <li key={d} className="bok-graph-legend-item">
            <svg width="28" height="10" aria-hidden="true">
              <line x1="0" y1="5" x2="28" y2="5" stroke="currentColor" strokeWidth={2} strokeDasharray={DASH_ARRAY[d]} />
            </svg>
            <span aria-hidden="true">{DERIVATION_META[d].glyph}</span> {DERIVATION_META[d].label}
          </li>
        ))}
      </ul>

      <div className="bok-graph-table-scroll">
      <table className="bok-graph-table" data-testid="capability-edges-table">
        <caption>Capability edges</caption>
        <thead>
          <tr>
            <th scope="col">Tool</th>
            <th scope="col">Capability</th>
            <th scope="col">Derivation</th>
            <th scope="col">Rationale</th>
          </tr>
        </thead>
        <tbody>
          {edges.map((edge, i) => (
            <tr key={`${edge.tool}-${edge.capability}-${i}`}>
              <td>
                {edge.tool}
                {flaggedTools.has(edge.tool) ? " (policy-flagged)" : ""}
              </td>
              <td>{CAPABILITY_LABEL[edge.capability]}</td>
              <td>
                <span aria-hidden="true">{DERIVATION_META[edge.derivation].glyph}</span>{" "}
                {DERIVATION_META[edge.derivation].label}
              </td>
              <td>{edge.rationale}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </div>
  );
}

interface ToolNodeProps {
  tool: string;
  x: number;
  y: number;
  flagged: boolean;
  onActivate: () => void;
}

function ToolNode({ tool, x, y, flagged, onActivate }: ToolNodeProps) {
  if (flagged) return <FlaggedToolNode tool={tool} x={x} y={y} onActivate={onActivate} />;
  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool"
      data-testid="node"
      role="button"
      tabIndex={0}
      aria-label={`Tool ${tool}`}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (!activates(event)) return;
        event.preventDefault();
        onActivate();
      }}
    >
      <circle r={16} />
      <text x={-24} dy="0.35em" textAnchor="end">
        {tool}
      </text>
    </g>
  );
}

type PulseState = "pending" | "playing" | "done" | "skipped";

/**
 * A policy-flagged tool pulses once, amber, on first render, then holds a
 * static ring -- one orchestrated moment, not scattered effects or a loop
 * (brief §7 screen 4).
 *
 * ponytail: pulse is a one-shot CSS animation keyed on first paint, not a
 * JS timer. A timer would re-fire on re-render and turn the one
 * orchestrated moment into a nervous tic, which is the exact failure 00
 * §5.3 warns about.
 */
function FlaggedToolNode({ tool, x, y, onActivate }: Omit<ToolNodeProps, "flagged">) {
  const [pulse, setPulse] = useState<PulseState>("pending");

  // useLayoutEffect (not useEffect): resolves before the browser paints, so
  // a reduced-motion viewer never sees `data-pulse` pass through "playing"
  // at all -- it goes straight from the unpainted "pending" first render to
  // "skipped".
  useLayoutEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    setPulse(reduced ? "skipped" : "playing");
  }, []);

  const ring = pulse === "done" || pulse === "skipped";

  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool bok-graph-node-flagged"
      data-testid="node-flagged"
      data-pulse={pulse}
      data-ring={ring}
      role="button"
      tabIndex={0}
      aria-label={`Tool ${tool}, policy-flagged`}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (!activates(event)) return;
        event.preventDefault();
        onActivate();
      }}
    >
      {pulse === "playing" && (
        <circle r={16} className="bok-graph-pulse-ring" onAnimationEnd={() => setPulse("done")} />
      )}
      {ring && <circle r={22} className="bok-graph-static-ring" />}
      <circle r={16} className="bok-graph-node-circle" />
      <text x={-24} dy="0.35em" textAnchor="end">
        {tool}
      </text>
    </g>
  );
}
