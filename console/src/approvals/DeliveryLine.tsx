// SPDX-License-Identifier: AGPL-3.0-only
// What an approval's page says about its announcements (#678): when the message reached its
// approvers against the deadline, and why one was never sent. Fixed copy over the server's
// counts; the times are the reader's own message, nothing about another person. Loaded after
// the page, on its own: what a cold approval link needs first is the request and the buttons.

import type { ApprovalDelivery, ApprovalItem } from "../api/types.gen";
import { Time } from "../components/ui/Time";
import { ago } from "../lib/time";

/** One sentence of the delivery line; `at`, when present, is printed between `lead` and `rest`. */
export interface DeliverySentence {
  lead: string;
  at?: string;
  rest?: string;
}

function destinations(count: number): string {
  return `${String(count)} destination${count === 1 ? "" : "s"}`;
}

function margin(seconds: number): string {
  return `${ago(Math.abs(seconds))} ${seconds >= 0 ? "before" : "after"} the deadline`;
}

/**
 * The delivery line, sentence by sentence. `pending` is whether the approval still waits, so
 * a message still queued on a closed approval is not described as being sent.
 */
export function deliveryLine(delivery: ApprovalDelivery | null | undefined, pending: boolean): DeliverySentence[] {
  if (delivery === null || delivery === undefined) return [{ lead: "Nobody was notified outside this console." }];
  const total = delivery.delivered + delivery.pending + delivery.failed + delivery.lapsed + delivery.closed + delivery.withdrawn;
  const said: DeliverySentence[] = [];
  if (delivery.delivered > 0) {
    const last = delivery.last_delivered_at;
    const by = delivery.margin_seconds;
    if (total === 1 && last !== null && by !== null) {
      said.push({ lead: "Notification delivered ", at: last, rest: `, ${margin(by)}.` });
    } else if (by !== null) {
      said.push({ lead: `Delivered to ${String(delivery.delivered)} of ${destinations(total)}, the last ${margin(by)}.` });
    } else {
      said.push({ lead: `Delivered to ${String(delivery.delivered)} of ${destinations(total)}.` });
    }
  }
  if (delivery.lapsed > 0) said.push({ lead: "Not sent: the approval lapsed before delivery." });
  if (delivery.closed > 0) said.push({ lead: "Not sent: decided before delivery." });
  if (delivery.withdrawn > 0) said.push({ lead: "Not sent: the request was no longer valid." });
  if (delivery.pending > 0 && pending) said.push({ lead: `Sending to ${destinations(delivery.pending)}.` });
  if (delivery.failed > 0) said.push({ lead: `${String(delivery.failed)} could not be delivered.` });
  return said;
}


/** The delivery line in words, the delivery time through the console's one time format (#678). */
export function DeliveryLine({ item }: { item: ApprovalItem }) {
  const said = deliveryLine(item.delivery, item.approval_state === "PENDING");
  if (said.length === 0) return null;
  return (
    <p className="muted quorum delivery-line">
      {said.map((sentence, index) => (
        <span key={index}>
          {index > 0 ? " " : ""}
          {sentence.lead}
          {sentence.at !== undefined ? <Time at={sentence.at} precision="second" /> : null}
          {sentence.rest ?? ""}
        </span>
      ))}
    </p>
  );
}
