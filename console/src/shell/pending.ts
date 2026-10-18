// SPDX-License-Identifier: AGPL-3.0-only
// The waiting count as the title and the bell read it (#678), in a module of its own so it loads
// with them and not with the shell's first frame. It observes the pill's own query, which the
// shell's counts keep on the page's one timer: the key is the same and this observer is switched
// off, so it asks for nothing of its own and joins no timer.

import { useQuery } from "@tanstack/react-query";

import { listApprovalsOptions } from "../api/@tanstack/react-query.gen";

/** The assigned pending queue as the title and the bell read it: its length, whether there is a
 * next page, and the soonest deadline in it. The same query as the pill, so no request of its own. */
export interface Pending {
  count: number | undefined;
  more: boolean;
  soonest: string | undefined;
  /** When the answer was read, so a change of space can tell its first answer from the last one's. */
  at: number;
}

export function usePending(): Pending {
  const approvals = useQuery({ ...listApprovalsOptions({ query: { view: "pending" } }), enabled: false });
  const items = approvals.data?.items;
  let soonest: string | undefined;
  for (const item of items ?? []) {
    if (soonest === undefined || Date.parse(item.expires_at) < Date.parse(soonest)) soonest = item.expires_at;
  }
  return {
    count: items?.length,
    more: (approvals.data?.next_cursor ?? null) !== null,
    soonest,
    at: approvals.dataUpdatedAt,
  };
}
