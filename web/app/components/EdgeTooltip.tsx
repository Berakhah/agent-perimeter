/**
 * Hovering or focusing a capability edge shows why the capability was
 * inferred -- schema, description, or probe are not the same claim and must
 * not look the same (brief §7 screen 4, B9). Rendered as a fixed panel
 * beneath the graph rather than a floating tooltip positioned in the SVG's
 * own coordinate space, which would need scale-aware math this small,
 * static layout has no other reason to carry.
 */
import { DERIVATION_META, type Derivation } from "@/src/lib/_bok-ui";

export interface EdgeTooltipProps {
  tool: string;
  capability: string;
  derivation: Derivation;
  rationale: string;
}

export function EdgeTooltip({ tool, capability, derivation, rationale }: EdgeTooltipProps) {
  const meta = DERIVATION_META[derivation];
  return (
    <div className="bok-edge-tooltip" data-testid="edge-tooltip" role="status">
      <strong>
        <span aria-hidden="true">{meta.glyph}</span> {tool} → {capability} · {meta.label}-derived
      </strong>
      <p>{rationale}</p>
    </div>
  );
}
