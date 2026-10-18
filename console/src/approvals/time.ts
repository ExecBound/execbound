// SPDX-License-Identifier: AGPL-3.0-only
// Time on the Approvals page: the server's clock ticking once a second while the tab is
// visible, the seconds an approval has left, and the age of a fact in round words.

import { clock, instant } from "../lib/time";

export { useServerNow } from "../lib/clock";

/** Whole seconds until an instant, never negative. */
export function secondsUntil(iso: string, now: number): number {
  return Math.max(0, Math.floor((Date.parse(iso) - now) / 1000));
}

export function secondsSince(iso: string, now: number): number {
  return Math.max(0, Math.floor((now - Date.parse(iso)) / 1000));
}

export { ago as age } from "../lib/time";

/** "14:07:31" in the chosen zone, only under a heading or caption that names it. */
export function timeOfDay(iso: string): string {
  return clock(iso);
}

/**
 * "2026-09-18 13:54:59 EDT": a moment with the day it fell on, in the chosen zone, for
 * something that happened far enough back that a time alone says nothing
 * (#426).
 */
export function stamp(iso: string): string {
  return instant(iso, "second");
}
