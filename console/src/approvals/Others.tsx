// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { ApprovalItem } from "../api/types.gen";
import { Badge, type Tone } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { can, useSession } from "../lib/session";
import { deliveryWord, LATE_NOTE_NO_LINK, lateLapse, lateNote } from "./delivery";

// Held requests too few people can decide, above the queue's chips for a workspace
// administrator (#678), in this chunk so the cold approval link never fetches it.
export { UnroutedNotice } from "../components/directory/UnroutedNotice";

// What only an administrator sees about approvals waiting on other people (#678), in a chunk of
// its own: an approver's cold link never fetches it.

/**
 * Who can decide a request waiting on others, in one phrase, for an administrator's row: the
 * first of these that holds (#678). Null for a reader the server gave no count, which is every
 * reader but an administrator.
 */
function coverage(item: ApprovalItem): { text: string; tone: Tone | null } | null {
  if (item.reviewers === null || item.reviewers === undefined) return null;
  if (item.reviewers === 0) return { text: "No one can approve this", tone: "deny" };
  if ((item.reviewers_left ?? 0) < item.required - item.recorded) return { text: "Cannot reach the quorum", tone: "deny" };
  return { text: `${String(item.reviewers)} assigned`, tone: null };
}

/** "0 of 1 approvals": the quorum so far, as a row says it. */
function quorumSoFar(item: Pick<ApprovalItem, "recorded" | "required">): string {
  return `${String(item.recorded)} of ${String(item.required)} approvals`;
}

/** Pending's empty state for an administrator whose queue is empty while others wait (#678). */
function notAssignedTitle(waiting: number): string {
  return `You are not assigned to review any of the ${String(waiting)} request${waiting === 1 ? "" : "s"} waiting here.`;
}

const NOT_ASSIGNED_BODY = "Administrators review only what they are assigned to. Open one to assign yourself, or see who reviews.";

/**
 * A row waiting on others: the approvals recorded so far, who can decide it, and whether the
 * message reached them (Delivered, Sending or Not sent).
 */
export function Coverage({ item }: { item: ApprovalItem }) {
  const covered = coverage(item);
  if (covered === null) return null;
  const sent = deliveryWord(item.delivery);
  return (
    <small>
      {quorumSoFar(item)}
      {" · "}
      <span className={covered.tone === null ? undefined : `tone-${covered.tone}`}>{covered.text}</span>
      {sent !== null ? ` · ${sent}` : null}
    </small>
  );
}

/**
 * Pending's empty state for an administrator whose queue is empty while requests wait on
 * others: exact by construction, since Waiting on others is precisely the pending approvals here
 * that the administrator does not review.
 */
export function NotAssigned({ waiting, onShow }: { waiting: number; onShow: () => void }) {
  return (
    <EmptyState title={notAssignedTitle(waiting)}>
      <p>{NOT_ASSIGNED_BODY}</p>
      <p className="row">
        <Button onClick={onShow}>Show waiting on others</Button> <Link to="/approvers">See who reviews</Link>
      </p>
    </EmptyState>
  );
}

/**
 * The badges on a row in an administrator's Lapsed view: its message came too late, and too few
 * people could decide it when it was held (#678).
 */
export function LateFlag({ item }: { item: ApprovalItem }) {
  return (
    <>
      {lateLapse(item) ? (
        <span className="queue-flag">
          <Badge tone="stale">Message late</Badge>
        </span>
      ) : null}
      <HoldFlag item={item} />
    </>
  );
}

/**
 * Above an administrator's Lapsed list, when any row's message was late (#678): how many, and
 * that a longer approval deadline gives people time to answer. A link to Workspace settings
 * only for a reader who can change the deadline there. Advice in fixed copy, said once.
 */
export function LateLapses({ items }: { items: ApprovalItem[] }) {
  const session = useSession();
  const late = items.filter(lateLapse).length;
  if (late === 0) return null;
  return (
    <p className="queue-note late-note" role="note">
      {lateNote(late)}{" "}
      {can(session, "workspace.manage") ? (
        <Link to="/tenant">Change it in Workspace settings.</Link>
      ) : (
        LATE_NOTE_NO_LINK
      )}
    </p>
  );
}

/**
 * The badge on a lapsed row that too few people could decide when it was held, in an
 * administrator's Lapsed view. The live count says who could decide it now; this says
 * why it lapsed. The server sends the count only to a workspace administrator.
 */
export function HoldFlag({ item }: { item: ApprovalItem }) {
  const recorded = item.reviewers_at_hold;
  if (recorded === null || recorded === undefined || recorded >= item.required) return null;
  return (
    <span className="queue-flag">
      <Badge tone="stale">
        {recorded === 0 ? "No one could approve this when it was held" : "Too few people could approve this when it was held"}
      </Badge>
    </span>
  );
}
