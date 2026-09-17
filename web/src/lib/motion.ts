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
import { useEffect, useState } from "react";

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
  // `null` only during SSR (no `window` to read `matchMedia` from); `?? false`
  // just picks the value this render starts from. The graph's fixture path
  // is server-rendered with real content, so this genuinely differs from
  // the client's real preference on first hydration for a reduced-motion
  // viewer -- `data-entered` below is built to survive that, not to assume
  // it never happens.
  const reduced = useReducedMotion() ?? false;
  const [entered, setEntered] = useState(false);
  const immediate = reduced || options.skip === true;
  // `data-entered` always starts "false" -- on some screens (the capability
  // graph's fixture path) this element is present in server-rendered HTML,
  // and `reduced`/`skip` are only known once the client hydrates. Starting
  // from "false" unconditionally means the very first render always agrees
  // with the server, so React has nothing to silently refuse to patch
  // (react.dev/link/hydration-mismatch); the effect below then commits the
  // real end state in the first post-mount render, which is a normal
  // client update, not a hydration diff, so it always lands. `immediate`
  // still governs the *visual* (initial/transition below) -- an immediate
  // viewer's content is already painted in its final state on mount, this
  // is only the attribute lagging one commit behind for correctness.
  useEffect(() => {
    if (immediate) setEntered(true);
  }, [immediate]);
  return {
    initial: immediate ? false : from,
    animate: to,
    transition: immediate
      ? { duration: 0 }
      : { duration: options.duration ?? DURATION_S.reveal, ease: "easeOut", delay: staggerDelay(options.index ?? 0) },
    onAnimationComplete: () => setEntered(true),
    "data-entered": entered ? "true" : "false",
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
