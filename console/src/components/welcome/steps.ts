// SPDX-License-Identifier: AGPL-3.0-only
// Getting started's four steps, as the address names them (#678). Kept apart from the rest of
// the setup words because the route's search check reads it, and the route tree is in every
// page's first load, an approval link opened cold included.

export const STEPS = ["example", "connect", "verify", "controls"] as const;
export type Step = (typeof STEPS)[number];

/** A step named in the address, kept only when it is one of the four. */
export function parseStep(value: unknown): Step | undefined {
  return typeof value === "string" && (STEPS as readonly string[]).includes(value) ? (value as Step) : undefined;
}
