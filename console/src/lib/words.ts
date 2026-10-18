// SPDX-License-Identifier: AGPL-3.0-only
// Words and tones for what the console API returns (#333). The server decides and
// names each state; the client only maps a state to the one badge tone colour is reserved
// for. Instants are formatted by lib/time.ts, in the zone the viewer chose.

import type { Tone } from "../components/ui/Badge";
import { ago, instant } from "./time";

export const RANGES = ["24h", "7d", "30d"] as const;
export type Range = (typeof RANGES)[number];
export const RANGE_WORDS: Record<Range, string> = { "24h": "24 hours", "7d": "7 days", "30d": "30 days" };

export function isRange(value: unknown): value is Range {
  return typeof value === "string" && (RANGES as readonly string[]).includes(value);
}

/** The badge tone of an execution state; colour is reserved for decisions (#333). */
export function toneFor(state: string): Tone {
  switch (state) {
    case "EXECUTED":
      return "allow";
    case "PENDING_APPROVAL":
    case "DISPATCH_COMMITTED":
    case "INDETERMINATE":
      return "hold";
    case "DENIED":
      return "deny";
    case "OBSERVED":
      return "obs";
    default:
      return "stale";
  }
}

export { clock as clockTime } from "./time";

/** An instant to the second, with its date and zone, in the zone the viewer chose. */
export function dateTime(iso: string): string {
  return instant(iso, "second");
}

/** How long ago an instant was, in one unit, rounding down. */
export function age(iso: string, now: Date = new Date()): string {
  return ago((now.getTime() - new Date(iso).getTime()) / 1000);
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/**
 * One figure against the same figure of the window before. `had` is what the window before
 * held in all: where it held nothing there is nothing to compare against, and "46 more than
 * the 7 days before" is filler dressed as a trend, so the line says what is true instead
 * (#427). An empty workspace has no
 * decisions at all, which is a different truth from a first week (#678).
 */
export function compared(current: number, previous: number, span: string, had = previous): string {
  if (had === 0) return current === 0 ? "No decisions yet" : `No earlier ${span} to compare`;
  const delta = current - previous;
  if (delta === 0) return `The same as the ${span} before`;
  return `${String(Math.abs(delta))} ${delta > 0 ? "more" : "fewer"} than the ${span} before`;
}

export function percent(part: number, whole: number): string {
  if (whole === 0) return "No decisions yet";
  return `${String(Math.round((part / whole) * 100))}% of decisions`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

export const SOURCE_WORDS: Record<string, string> = {
  inventory: "Inventory",
  incident: "Incident register",
  signal: "Security signal",
};

export function sourceWord(kind: string): string {
  return SOURCE_WORDS[kind] ?? kind;
}

/**
 * An approval's state in the approval flow's own words (#678): a person approves or refuses, an
 * approval whose deadline passed undecided has lapsed. The recorded codes are unchanged; only
 * the words a page prints for them are these.
 */
export const APPROVAL_WORDS: Readonly<Record<string, string>> = {
  PENDING: "Waiting for a person",
  APPROVED: "Approved",
  CONSUMED: "Approved",
  DENIED: "Refused",
  EXPIRED: "Lapsed",
  INVALIDATED: "No longer valid",
};

/** A person's answer to an approval, as a verb in a sentence. */
export const VERDICT_WORDS: Readonly<Record<"APPROVE" | "DENY", string>> = {
  APPROVE: "approve",
  DENY: "refuse",
};

/** A person's recorded answer, as a past participle: "User 2: approved". */
export const DECIDED_WORDS: Readonly<Record<"APPROVE" | "DENY", string>> = {
  APPROVE: "approved",
  DENY: "refused",
};

// The console's term list lives in `./terms`, so a page's first load does not carry it; it is
// re-exported here unchanged (#678).
export { TERMS } from "./terms";
