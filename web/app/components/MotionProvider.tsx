"use client";

/**
 * `MotionConfig reducedMotion="user"` disables transform/layout animations
 * for viewers who asked for reduced motion, app-wide. It is the safety net
 * under `src/lib/motion.ts` (which is the real reduced-motion contract:
 * final state on first paint), not a replacement for it -- MotionConfig
 * still lets opacity animate, which is not "immediately legible".
 * Separate file because `app/layout.tsx` is a server component and
 * MotionConfig needs a client boundary.
 */
import { MotionConfig } from "motion/react";
import type { ReactNode } from "react";

export function MotionProvider({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user">{children}</MotionConfig>;
}
