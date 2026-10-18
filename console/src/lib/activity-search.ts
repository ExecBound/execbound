// SPDX-License-Identifier: AGPL-3.0-only
// The Activity page's search parameters (#333): the filters, the cursor and the
// open drawer all live in the URL, so a link or the back button restores them. The values
// are the console API's own vocabulary; anything else is dropped rather than sent.

export const ACTIVITY_STATES = [
  "UNCERTAIN",
  "PENDING_APPROVAL",
  "DISPATCH_COMMITTED",
  "INDETERMINATE",
  "EXECUTED",
  "FAILED_NOT_EXECUTED",
  "FAILED_EFFECT_UNKNOWN",
  "DENIED",
  "STALE_AUTHORIZATION",
  "OBSERVED",
] as const;
export type ActivityState = (typeof ACTIVITY_STATES)[number];

export const SINCE = ["1h", "24h", "7d", "30d"] as const;
export type Since = (typeof SINCE)[number];

/**
 * What became of a request, as the value report counts it (#678): the server's closed list,
 * each opening exactly the rows its count holds.
 */
export const OUTCOMES = [
  "refused_policy",
  "refused_limit",
  "refused_busy",
  "approved",
  "refused_by_person",
  "lapsed",
  "approved_unused",
  "closed",
  "waiting",
  "settled",
  "unsettled_now",
  "effect_unknown",
  "would_refuse",
  "would_refuse_by_limit",
  "would_hold",
  "would_run",
] as const;
export type Outcome = (typeof OUTCOMES)[number];

export function isOutcome(value: unknown): value is Outcome {
  return typeof value === "string" && (OUTCOMES as readonly string[]).includes(value);
}

export interface ActivitySearch {
  state?: ActivityState;
  outcome?: Outcome;
  /** An instant with its zone: requests made after it, the start of a report's window. */
  from?: string;
  action?: string;
  agent?: string;
  target?: string;
  since?: Since;
  cursor?: string;
  open?: string;
}

export function isActivityState(value: unknown): value is ActivityState {
  return typeof value === "string" && (ACTIVITY_STATES as readonly string[]).includes(value);
}

export function isSince(value: unknown): value is Since {
  return typeof value === "string" && (SINCE as readonly string[]).includes(value);
}

function text(value: unknown, max = 200): string | undefined {
  return typeof value === "string" && value !== "" && value.length <= max ? value : undefined;
}

/** An instant the list can be asked for: at most 40 characters, and one `Date.parse` reads. */
function instantText(value: unknown): string | undefined {
  const found = text(value, 40);
  return found !== undefined && !Number.isNaN(Date.parse(found)) ? found : undefined;
}

export function activitySearch(search: Record<string, unknown>): ActivitySearch {
  return {
    state: isActivityState(search.state) ? search.state : undefined,
    outcome: isOutcome(search.outcome) ? search.outcome : undefined,
    from: instantText(search.from),
    action: text(search.action, 80),
    agent: text(search.agent, 36),
    target: text(search.target, 36),
    since: isSince(search.since) ? search.since : undefined,
    cursor: text(search.cursor),
    open: text(search.open, 36),
  };
}
