// SPDX-License-Identifier: AGPL-3.0-only
// The production workstation's line in Verify protection (#545): how long a held sample
// request can wait for approval, and which approval is its. Words and lookups; the reads are
// `readTenant` and `listApprovals`, both an administrator's already. Also the one clock the
// sample facts' staleness is judged by, and what to do when a policy stops a refresh, both shared
// by Verify protection and the Sample targets card.

import { useEffect, useState } from "react";

import type { ApprovalItem, SampleHostView, SampleStatusView } from "../../api/types.gen";
import { serverNow } from "../../lib/clock";
import { dateTime, plural } from "../../lib/words";

/**
 * When the sample facts went stale, or null while they are current. Judged as the server judges a
 * plan's facts, stale from the instant `now >= valid_until` (`admission`, `snapshot`), and by the
 * server's clock (`lib/clock`, which every response's `Date` header sets and which is already in
 * the entry chunk), so a browser whose clock is wrong still says stale when the server starts
 * refusing. Read again every half minute: nothing else re-renders a page left open when the facts
 * go stale, and an unchanged poll of the status re-renders nothing. `approvals/time`'s hook would
 * do the same, but importing it here moves it into a chunk the cold approval link shares
 * (measured: 0.2 KB core, 0.3 KB hosted).
 */
export function useStaleSince(staleAt: string | null): string | null {
  const [now, setNow] = useState(serverNow);
  useEffect(() => {
    const id = setInterval(() => { setNow(serverNow()); }, 30_000);
    return () => { clearInterval(id); };
  }, []);
  return staleAt !== null && Date.parse(staleAt) <= now ? staleAt : null;
}

/**
 * The way past a refresh refused for a policy a person made (#545). Set your controls'
 * "copy your active policy" and its templates (`current-protections`, `review-all`) copy the
 * starter policy's mappings, so the draft names the sample connection, and while any such bundle
 * is not retired a refresh is refused `POLICY_PRESENT` (`samples._PERSONS_POLICY`). Retiring one
 * lets it through. A bundle a Space selects cannot be retired (`policy.store.retire_bundle`), and
 * activating another in its place deselects it; that has to be the starter policy, since the
 * refresh's own install refuses a workspace any other policy is active in (`samples_install`).
 */
export const RETIRE_TO_REFRESH =
  "A policy made from the starter policy, by copying it or from a template, stops a refresh until it is retired in Policies; if it is the active policy, activate the starter policy again first, then retire it.";

/**
 * A held request runs only when the agent sends the identical request again after a person has
 * approved it, before the approval's deadline (the agent guide's "Approvals"), so it lapses in
 * either case: nobody approved it in time, or it was approved and the agent never came back.
 */
const LAPSES =
  "If nobody approves it in time, or it is approved but your agent does not send it again before the deadline, it lapses, and your agent has to make a new request.";

/** A deadline in its largest whole unit: "2 minutes", "1 hour", "150 seconds". */
export function span(seconds: number): string {
  if (seconds % 3600 === 0) return plural(seconds / 3600, "hour");
  if (seconds % 60 === 0) return plural(seconds / 60, "minute");
  return plural(seconds, "second");
}

/**
 * How long a held request can wait. `seconds` is `readTenant`'s `deadline.seconds`: a number,
 * null where the workspace turned the deadline off, and undefined until the tenant has been read.
 * The session's `approval_deadline_seconds` is never used: it reads the default, 120, where the
 * deadline is off. An approval never outlives the plan it was decided on (`store.approval_expiry`),
 * whose validity ends when its facts go stale or the agent's key expires, whichever is first
 * (`snapshot.py`), so `staleAt` is a bound in every case, never a promise. The caller passes null
 * for `staleAt` once the facts are stale: a moment already gone bounds nothing, and the next
 * facts' stale time is not known until they are refreshed.
 */
export function deadlineWords(seconds: number | null | undefined, staleAt: string | null): string {
  const stale = staleAt === null ? null : dateTime(staleAt);
  if (seconds === undefined) {
    return stale === null ? LAPSES : `A request never waits past ${stale}, when the sample facts go stale. ${LAPSES}`;
  }
  if (seconds === null) {
    return stale === null
      ? `This workspace has no approval deadline, so a request waits for approval no later than the moment its facts go stale. ${LAPSES}`
      : `This workspace has no approval deadline, so a request waits for approval no later than ${stale}, when the sample facts go stale. ${LAPSES}`;
  }
  const cap = stale === null ? "" : `, and never past ${stale}, when the sample facts go stale`;
  return `A request waits for approval for up to ${span(seconds)}, this workspace's approval deadline${cap}. ${LAPSES}`;
}

/**
 * The newest approval on this sample target made since its facts were recorded. The lists are
 * newest first; one made before `observed_at` belongs to samples since removed or refreshed,
 * whose targets had the same `provider_id`.
 */
export function sampleApproval(items: readonly ApprovalItem[] | undefined, samples: SampleStatusView, host: SampleHostView): ApprovalItem | undefined {
  const since = samples.observed_at === null ? Number.NEGATIVE_INFINITY : Date.parse(samples.observed_at);
  return items?.find((item) => item.target === host.provider_id && Date.parse(item.created_at) >= since);
}

/**
 * The lapsed approval that still holds the samples: one nothing has ended yet, so its request is
 * still `PENDING_APPROVAL`, which is the only way the Lapsed list holds an approval that is not
 * `EXPIRED` (`human.records`). An ended one stays in that list for good, and a sentence about it
 * would be wrong advice once a newer request has gone through, so it is never named.
 */
export function blockingApproval(items: readonly ApprovalItem[] | undefined, samples: SampleStatusView, host: SampleHostView): ApprovalItem | undefined {
  return sampleApproval(items?.filter((item) => item.approval_state !== "EXPIRED"), samples, host);
}
