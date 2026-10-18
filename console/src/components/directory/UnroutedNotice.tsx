// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { readUnroutedApprovalsOptions } from "../../api/@tanstack/react-query.gen";
import type { UnroutedApprovals, UnroutedRecord } from "../../api/types.gen";
import { usePolledQuery } from "../../lib/poll";
import { can, useSession } from "../../lib/session";
import { COVERAGE_ID } from "./coverage-id";

/**
 * Held requests too few people can decide, for a workspace administrator (#678).
 *
 * Read on the page's shared timer, so it asks for nothing in a hidden tab, and only by a
 * session with workspace-wide `access.manage`: an approver and an administrator narrowed to
 * Spaces make no call at all, and the server would refuse them.
 */
export function useUnrouted() {
  const allowed = can(useSession(), "access.manage");
  return usePolledQuery({ ...readUnroutedApprovalsOptions(), enabled: allowed });
}

/** Whether the line has anything to say. */
export function unroutedShown(data: UnroutedApprovals | undefined): boolean {
  return data !== undefined && (data.pending > 0 || data.recent > 0);
}

function requests(count: number): string {
  return `${String(count)} held ${count === 1 ? "request" : "requests"}`;
}

/** "fewer people can decide it than it needs", agreeing with the count. */
function fewer(count: number, verb: "can decide" | "who could decide"): string {
  return count === 1 ? `fewer people ${verb} it than it needs` : `fewer people ${verb} them than they need`;
}

function RecordLink({ record }: { record: UnroutedRecord }) {
  return (
    <Link to="/activity" search={{ open: record.execution_id }}>
      {record.request_ref}
    </Link>
  );
}

function ChooseReviewers() {
  return (
    <Link to="/approvers" hash={COVERAGE_ID}>
      Choose reviewers
    </Link>
  );
}

/** The line itself, from an answer the caller already holds. */
export function UnroutedLine({ data }: { data: UnroutedApprovals | undefined }) {
  if (data === undefined || !unroutedShown(data)) return null;
  if (data.pending > 0) {
    const sentence =
      data.pending_nobody === data.pending
        ? `No one can approve ${requests(data.pending)}.`
        : `${requests(data.pending)} cannot reach ${data.pending === 1 ? "its" : "their"} quorum: ${fewer(data.pending, "can decide")}.`;
    return (
      <p className="note unrouted-line">
        {sentence}{" "}
        {data.pending_latest !== null ? (
          <>
            <RecordLink record={data.pending_latest} />: open the record ·{" "}
          </>
        ) : null}
        <ChooseReviewers />
      </p>
    );
  }
  return (
    <p className="note unrouted-line">
      In the last 7 days, {requests(data.recent)} had {fewer(data.recent, "who could decide")}.{" "}
      {data.recent_latest !== null ? (
        <>
          Latest: <RecordLink record={data.recent_latest} /> ·{" "}
        </>
      ) : null}
      <ChooseReviewers />
    </p>
  );
}

/** The line with its own read, for a page that holds no answer of its own (Approvals). */
export function UnroutedNotice() {
  const unrouted = useUnrouted();
  return <UnroutedLine data={unrouted.data} />;
}
