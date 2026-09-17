"use client";

/**
 * The single place `motion`'s `useReducedMotion()` is consulted (spec
 * 2026-09-16-web-ui-redesign §5, rule 1). Screens never write a bare
 * `<motion.x initial={...}>`; they spread one of the hooks below, which
 * already (a) render the final state on first paint under reduced motion,
 * (b) cap stagger so a long list never takes more than STAGGER_CAP_S to
 * settle, and (c) expose `data-entered` so a Playwright test can assert the
 * end state without inspecting pixels.
 *
 * Timings are the spec's §2 numbers: hover 150ms, state 200ms, reveal
 * 300ms, edge 400ms, ≤40ms/item stagger. Easing is always easeOut -- no
 * overshoot anywhere (spec D3).
 */
import { useReducedMotion, type Transition } from "motion/react";
import { useState } from "react";

export const DURATION_S = { hover: 0.15, state: 0.2, reveal: 0.3, edge: 0.4 } as const;
export const STAGGER_S = 0.04;
export const STAGGER_CAP_S = 0.4;

/** Per-item delay for the item at `index`, capped so the whole list settles inside STAGGER_CAP_S. */
export function staggerDelay(index: number): number {
  return Math.min(Math.max(index, 0) * STAGGER_S, STAGGER_CAP_S);
}

export interface EntranceTarget {
  opacity: number;
  y?: number;
  scale?: number;
  // Index signature only to satisfy motion's `Target` (which allows CSS
  // custom properties); none of the hooks below ever set one.
  [cssVariable: `--${string}`]: string | number;
}

export interface EntranceOptions {
  /** Position in the list, for stagger. Default 0. */
  index?: number;
  /** Seconds. Default DURATION_S.reveal. */
  duration?: number;
  /**
   * Render the end state with no animation even when motion is allowed --
   * FindingsTable uses this for a virtualizer remount of a row that has
   * already been revealed once (spec §4.3).
   */
  skip?: boolean;
}

export interface EntranceProps {
  initial: false | EntranceTarget;
  animate: EntranceTarget;
  transition: Transition;
  onAnimationComplete: () => void;
  "data-entered": "true" | "false";
}

function useEntrance(from: EntranceTarget, to: EntranceTarget, options: EntranceOptions): EntranceProps {
  // `null` only during SSR; every animated element on these screens is
  // client-rendered after a fetch/stream, so treating null as "not reduced"
  // never paints a reduced-motion viewer's content at opacity 0.
  const reduced = useReducedMotion() ?? false;
  const [entered, setEntered] = useState(false);
  const immediate = reduced || options.skip === true;
  return {
    initial: immediate ? false : from,
    animate: to,
    transition: immediate
      ? { duration: 0 }
      : { duration: options.duration ?? DURATION_S.reveal, ease: "easeOut", delay: staggerDelay(options.index ?? 0) },
    onAnimationComplete: () => setEntered(true),
    "data-entered": immediate || entered ? "true" : "false",
  };
}

/** Opacity 0→1 with an 8px rise. List rows (spec §4.2, §4.3). */
export function useRiseIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0, y: 8 }, { opacity: 1, y: 0 }, options);
}

/** Opacity 0→1 with scale 0.95→1. Graph nodes (spec §4.4). */
export function useScaleIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0, scale: 0.95 }, { opacity: 1, scale: 1 }, options);
}

/** Opacity only. Status-frame swaps and graph edges (spec §4.2, §4.4). */
export function useFadeIn(options: EntranceOptions = {}): EntranceProps {
  return useEntrance({ opacity: 0 }, { opacity: 1 }, { duration: DURATION_S.state, ...options });
}
