// SPDX-License-Identifier: AGPL-3.0-only
// What an administrator's approval rows say about delivery (#678): the word a row waiting on
// others carries, and the late-lapse flag and note in the Lapsed view. Fixed copy over the
// server's counts. The detail's delivery line is `DeliveryLine.tsx`'s.

import type { ApprovalDelivery, ApprovalItem } from "../api/types.gen";

/** The threshold the server's `late` flag uses, as the late-lapse note says it. */
export const LATE_DELIVERY_SECONDS = 30;

/** The one word a row waiting on others carries: Delivered, Sending or Not sent. */
export function deliveryWord(delivery: ApprovalDelivery | null | undefined): string | null {
  if (delivery === null || delivery === undefined) return null;
  if (delivery.delivered > 0) return "Delivered";
  if (delivery.pending > 0) return "Sending";
  return "Not sent";
}

/**
 * Whether a lapsed row is flagged for an administrator: its message was late, and the clock
 * that ran out is the approval deadline, which the workspace setting lengthens. A context
 * validity clock is not, so those rows are not flagged.
 */
export function lateLapse(item: Pick<ApprovalItem, "delivery" | "deadline_clock">): boolean {
  return item.delivery?.late === true && item.deadline_clock === "approval deadline";
}

/** The line above an administrator's Lapsed list when any row is flagged. */
export function lateNote(count: number): string {
  return (
    `${String(count)} of these lapsed with the message delivered within ${String(LATE_DELIVERY_SECONDS)} seconds of the deadline, ` +
    "after it, or lapsed before it was sent. A longer approval deadline gives people time to answer."
  );
}

/** The note's ending for a reader who cannot change the deadline. */
export const LATE_NOTE_NO_LINK = "A workspace administrator can change the approval deadline.";
