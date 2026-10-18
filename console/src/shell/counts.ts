// SPDX-License-Identifier: AGPL-3.0-only
// The count pills in the sidebar and the tab bar (#333), on the page's one
// polling timer, so a count lands with the page's own reads rather than on a timer of its
// own (#427). Monitoring's count is the
// tenant's open findings, read from the tenant view an administrator already has, so no new
// route and nothing for an approver, who never sees the entry. Approvals is the pending
// queue's length, capped by the page size that route answers with. Both human account kinds
// ask for their assigned queue; administrators also read monitoring. The Approvals page
// shares the same query rather than asking for another copy.
//
// The tenant read is **not** on that timer. It carries the tenant's name, its enforcement
// mode and its stop, which change when an administrator changes them and not every ten
// seconds, and the two things that do change it already invalidate it: acknowledging a
// finding invalidates this query, and a mode, deadline or stop change writes the answer
// straight into it. What is left is a returning reader, whom `refetchOnWindowFocus`
// brings up to date. It was the one endpoint the second measurement on
// #427 found newly in the poll set.

import { useQuery } from "@tanstack/react-query";

import { listApprovalsOptions, readTenantOptions } from "../lib/shell-api";
import { POLL_MS, usePolledQuery } from "../lib/poll";
import { useSession } from "../lib/session";
import type { Counts } from "./Sidebar";

export const COUNT_INTERVAL_MS = POLL_MS;
/** How long the sidebar's tenant read stays fresh without asking again. */
export const TENANT_STALE_MS = 60_000;

export function useCounts(): Counts {
  const session = useSession();
  const tenant = useQuery({
    ...readTenantOptions(),
    enabled: session.role === "ADMIN",
    refetchInterval: false,
    staleTime: TENANT_STALE_MS,
  });
  const approvals = usePolledQuery({
    ...listApprovalsOptions({ query: { view: "pending" } }),
    staleTime: 5_000,
  });
  const counts: Counts = {};
  if (tenant.data !== undefined) {
    counts.monitoring = tenant.data.monitoring.open_findings;
    // Monitoring's quiet items (#678): stale sources plus overdue connections, which the
    // Monitoring entry counts when no finding is open.
    counts.quiet = tenant.data.monitoring.stale + tenant.data.monitoring.overdue;
  }
  if (approvals.data !== undefined) counts.approvals = approvals.data.items.length;
  return counts;
}
