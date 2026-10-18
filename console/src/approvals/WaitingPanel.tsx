// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useState } from "react";

import type { ApprovalDetail, ApprovalItem } from "../api/types.gen";
import { Button } from "../components/ui/Button";
import { can, useSession } from "../lib/session";
import { CopyApprovalLink } from "./CopyApprovalLink";
import { DeliveryLine } from "./DeliveryLine";

const AssignYourself = lazy(() => import("./AssignYourself"));

/** The Waiting panel's second sentence: who can decide, or why nobody can. */
export function waitingSentence(item: ApprovalItem, space: string): string {
  const reviewers = item.reviewers ?? 0;
  const left = item.reviewers_left ?? 0;
  const so = `${String(item.recorded)} of ${String(item.required)} approvals recorded`;
  if (reviewers === 0) {
    return `No one can approve this: nobody who can open this request holds a review assignment for this action and target in ${space}.`;
  }
  if (left < item.required - item.recorded) {
    return `This request cannot reach its quorum: ${so} and ${String(left)} assigned ${left === 1 ? "person has" : "people have"} not decided.`;
  }
  return `${String(reviewers)} ${reviewers === 1 ? "person is" : "people are"} assigned. ${so}.`;
}


/**
 * In place of the decision bar, for an administrator reading an approval they are not assigned
 * to decide (#678): who can decide it, or why nobody can, and the one assignment that would let
 * them decide it themselves. Not pinned on a phone: there is nothing here to press in a hurry.
 *
 * The assignment is the person page's own write, behind its step-up and audited, offered only
 * where it would land in this approval's space and the session may make it there. Nothing is
 * ever assigned without the confirmation, which says first when the write moves a review the
 * reader holds in another space.
 *
 * Loaded on demand: only an administrator reading outside their own assignments ever sees it,
 * so a cold approval link does not pay for it. The space switch is the page's own, passed in, so
 * this chunk asks for nothing the shell has not already loaded.
 */
export default function WaitingPanel({
  detail,
  switching,
  onSwitch,
}: {
  detail: ApprovalDetail;
  switching: boolean;
  onSwitch: (space: { space_id: string; name: string }) => void;
}) {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const space = detail.space;
  const spaceName = space?.name ?? session.tenant.name;
  const here = session.spaces <= 1 || space === null || session.space?.id === space.space_id;
  const allowed = can(session, "access.manage");
  return (
    <section className="card waiting-panel" aria-labelledby="waiting-title">
      <header className="card-head">
        <h2 id="waiting-title" className="card-title">
          You are not assigned to decide this request.
        </h2>
      </header>
      <div className="card-body">
      <p>{waitingSentence(detail.item, spaceName)}</p>
      <DeliveryLine item={detail.item} />
      <CopyApprovalLink linkPath={detail.link_path} approvalId={detail.item.approval_id} />
      <div className="row">
        {!here ? (
          <Button
            disabled={switching}
            onClick={() => {
              onSwitch(space);
            }}
          >
            Switch to <bdi>{space.name}</bdi> to assign yourself
          </Button>
        ) : (
          <>
            <Button
              disabled={!allowed}
              aria-describedby={allowed ? undefined : "waiting-cannot-assign"}
              onClick={() => {
                setOpen(true);
              }}
            >
              Assign yourself to review this
            </Button>
            {allowed ? null : (
              <span id="waiting-cannot-assign" className="muted">
                Your role in <bdi>{spaceName}</bdi> cannot assign reviewers.
              </span>
            )}
          </>
        )}
      </div>
      {open ? (
        <Suspense fallback={null}>
          <AssignYourself
            detail={detail}
            spaceName={spaceName}
            onClose={() => {
              setOpen(false);
            }}
          />
        </Suspense>
      ) : null}
      </div>
    </section>
  );
}
