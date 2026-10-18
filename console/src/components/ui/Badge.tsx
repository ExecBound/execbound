// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

/** Colour is reserved for decisions (#333); every tone is one of them. */
export type Tone = "allow" | "hold" | "deny" | "obs" | "stale" | "accent";

/** A word-first status badge: the word carries the meaning, the dot repeats it in colour. */
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`badge badge-${tone}`}>
      <span className="badge-dot" aria-hidden="true" />
      {children}
    </span>
  );
}
