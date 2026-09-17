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
import { motion } from "motion/react";
import { useLayoutEffect, useMemo, useState, type KeyboardEvent } from "react";

import { DERIVATION_META, type Derivation } from "@/src/lib/_bok-ui";
import type { Capability, CapabilityEdge } from "@/src/lib/api";
import { useFadeIn, useScaleIn } from "@/src/lib/motion";
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

/**
 * This graph renders its fixture content synchronously on first paint (see
 * `graph/page.tsx`, so the keyboard test's immediate Tab press has a node to
 * land on), unlike other screens' entrance-animated elements, which only
 * ever mount after a client fetch/stream completes and so never have
 * server-rendered markup to hydrate against. That makes this the one place
 * `useScaleIn`/`useFadeIn`'s reduced-motion detection (client-only
 * `matchMedia`, unknown during SSR) can disagree with the server-rendered
 * `data-entered`: React's hydration diff logs that mismatch and does not
 * repair it -- "won't be patched up" (react.dev/link/hydration-mismatch)
 * -- and, having recorded the *new* value as already-applied to the fiber,
 * no later re-render (a `useLayoutEffect` correction included, tried and
 * measured flaky here) touches that attribute again either.
 *
 * This module-level statement runs once, synchronously, the moment the
 * browser evaluates this script -- which happens while parsing/executing
 * the page's scripts, strictly before React hydrates anything (imports run
 * before the code that uses them). At that point the server-rendered
 * `data-entered="false"` is already sitting in the DOM (the browser painted
 * it from the raw HTML, no JS involved yet); this corrects it directly via
 * the DOM API, bypassing React's props entirely, before hydration ever
 * gets a chance to compare against it. `motion`'s own inline `opacity`
 * style doesn't need the same treatment -- it's already applied
 * imperatively via a ref, independent of this hydration-diff issue.
 */
if (typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  document
    .querySelectorAll('[data-testid="node"], [data-testid="node-flagged"], [data-testid="edge"], .bok-graph-node-inner')
    .forEach((el) => el.setAttribute("data-entered", "true"));
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

  // Pointer-hovered or keyboard-focused tool; its edges are marked
  // connected, every other edge dimmed (spec §4.4). Keyboard sets it too,
  // so the highlight is not a pointer-only affordance.
  const [highlightedTool, setHighlightedTool] = useState<string | null>(null);

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
        {toolOrder.map((tool, index) => (
          <ToolNode
            key={tool}
            tool={tool}
            index={index}
            x={TOOL_X}
            y={toolY.get(tool) ?? TOP_PAD}
            flagged={flaggedTools.has(tool)}
            onActivate={() => onActivateTool(tool)}
            onHighlight={setHighlightedTool}
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
        {edges.map((edge, i) => (
          <Edge
            key={`${edge.tool}-${edge.capability}-${i}`}
            edge={edge}
            index={i}
            y1={toolY.get(edge.tool) ?? TOP_PAD}
            y2={capY.get(edge.capability) ?? TOP_PAD}
            highlightedTool={highlightedTool}
            onActive={setActiveEdge}
          />
        ))}
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

interface EdgeProps {
  edge: CapabilityEdge;
  index: number;
  y1: number;
  y2: number;
  highlightedTool: string | null;
  onActive: (update: (current: CapabilityEdge | null) => CapabilityEdge | null) => void;
}

/**
 * One edge. Entrance is an opacity fade (spec §4.4): `strokeDasharray` is
 * the derivation encoding and is never animated. Dimming uses
 * `stroke-opacity` in CSS so it doesn't fight the inline `opacity` motion
 * owns. `onActive` takes a functional update so leaving/blurring one edge
 * never clears a different edge that became active in between.
 */
function Edge({ edge, index, y1, y2, highlightedTool, onActive }: EdgeProps) {
  const fade = useFadeIn({ index, duration: 0.4 });
  const connected = highlightedTool === edge.tool;
  const dimmed = highlightedTool !== null && !connected;
  const clearIfCurrent = () => onActive((current) => (current === edge ? null : current));
  return (
    <motion.line
      {...fade}
      data-testid="edge"
      data-derivation={edge.derivation}
      data-tool={edge.tool}
      data-connected={connected}
      data-dimmed={dimmed}
      className="bok-graph-edge"
      x1={TOOL_X}
      y1={y1}
      x2={CAP_X}
      y2={y2}
      strokeDasharray={DASH_ARRAY[edge.derivation]}
      tabIndex={0}
      aria-label={`${edge.tool} has ${CAPABILITY_LABEL[edge.capability]}, ${DERIVATION_META[edge.derivation].label}-derived: ${edge.rationale}`}
      onMouseEnter={() => onActive(() => edge)}
      onMouseLeave={clearIfCurrent}
      onFocus={() => onActive(() => edge)}
      onBlur={clearIfCurrent}
    >
      <title>{`${DERIVATION_META[edge.derivation].label}: ${edge.rationale}`}</title>
    </motion.line>
  );
}

interface ToolNodeProps {
  tool: string;
  index: number;
  x: number;
  y: number;
  flagged: boolean;
  onActivate: () => void;
  onHighlight: (tool: string | null) => void;
}

function ToolNode({ tool, index, x, y, flagged, onActivate, onHighlight }: ToolNodeProps) {
  // Unconditional hook call (rules of hooks); unused on the flagged path,
  // where FlaggedToolNode owns its own entrance.
  const entrance = useScaleIn({ index });
  if (flagged) {
    return <FlaggedToolNode tool={tool} index={index} x={x} y={y} onActivate={onActivate} onHighlight={onHighlight} />;
  }
  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool"
      data-testid="node"
      data-entered={entrance["data-entered"]}
      role="button"
      tabIndex={0}
      aria-label={`Tool ${tool}`}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (!activates(event)) return;
        event.preventDefault();
        onActivate();
      }}
      onMouseEnter={() => onHighlight(tool)}
      onMouseLeave={() => onHighlight(null)}
      onFocus={() => onHighlight(tool)}
      onBlur={() => onHighlight(null)}
    >
      {/* Inner group carries the entrance: motion writes style.transform,
          which would override the positioning `transform` attribute above. */}
      <motion.g {...entrance} className="bok-graph-node-inner">
        <circle r={16} />
        <text x={-24} dy="0.35em" textAnchor="end">
          {tool}
        </text>
      </motion.g>
    </g>
  );
}

type PulseState = "pending" | "playing" | "done" | "skipped";

/**
 * A policy-flagged tool pulses once, amber, after its entrance completes,
 * then holds a static ring -- one orchestrated moment, sequenced, never
 * stacked (spec §4.4; brief §7 screen 4).
 *
 * ponytail: pulse is a one-shot CSS animation keyed on the entrance's
 * completion, not a JS timer. A timer would re-fire on re-render and turn
 * the one orchestrated moment into a nervous tic, which is the exact
 * failure 00 §5.3 warns about.
 */
function FlaggedToolNode({ tool, index, x, y, onActivate, onHighlight }: Omit<ToolNodeProps, "flagged">) {
  const [pulse, setPulse] = useState<PulseState>("pending");
  const entrance = useScaleIn({ index });

  // useLayoutEffect (not useEffect): resolves before the browser paints, so
  // a reduced-motion viewer never sees `data-pulse` pass through "playing"
  // at all -- it goes straight from the unpainted "pending" first render to
  // "skipped". A motion-allowed viewer stays "pending" here; the entrance's
  // onAnimationComplete below is what starts the pulse (spec §4.4:
  // entrance → pulse, sequenced, never stacked).
  useLayoutEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) setPulse("skipped");
  }, []);

  const ring = pulse === "done" || pulse === "skipped";

  return (
    <g
      transform={`translate(${x}, ${y})`}
      className="bok-graph-node-tool bok-graph-node-flagged"
      data-testid="node-flagged"
      data-entered={entrance["data-entered"]}
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
      onMouseEnter={() => onHighlight(tool)}
      onMouseLeave={() => onHighlight(null)}
      onFocus={() => onHighlight(tool)}
      onBlur={() => onHighlight(null)}
    >
      <motion.g
        {...entrance}
        className="bok-graph-node-inner"
        onAnimationComplete={() => {
          entrance.onAnimationComplete();
          setPulse((current) => (current === "pending" ? "playing" : current));
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
      </motion.g>
    </g>
  );
}
