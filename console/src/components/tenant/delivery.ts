// SPDX-License-Identifier: AGPL-3.0-only
import type { NotificationDelivery, NotificationDestination } from "../../api/types.gen";
import { count } from "../../lib/when";

/**
 * How fast this workspace's approval notifications arrive, in words (#678). Pure functions
 * with no React, so Workspace settings, its deadline dialog, guided setup and a later readiness
 * card read one copy. Every figure is the server's measurement; nothing here comes from a string
 * an operator or the server supplied.
 */

/** The kinds a destination announces approvals through; the audit export announces none. */
const APPROVAL_KINDS = new Set(["webhook", "email", "slack", "teams"]);

/** What each message a destination may receive is called, in the server's order. */
export const MESSAGE_LABELS: Record<NotificationDestination["messages"][number], string> = {
  pending: "New requests",
  reminder: "Reminders",
  closed: "Outcomes",
};

/**
 * The deadline the dialog warns under: three times the measured 90th percentile, so at least two
 * thirds of the window remain after nine in ten notifications have arrived, for an approver to
 * read the message, open the page and decide.
 */
export const DELIVERY_MULTIPLE = 3;

/** A duration in seconds under two minutes, whole minutes rounded up from two minutes. */
export function durationWords(seconds: number): string {
  return seconds < 120 ? `${String(seconds)} s` : `${String(Math.ceil(seconds / 60))} min`;
}

/** Whether any destination announces approvals. */
export function announces(destinations: readonly NotificationDestination[]): boolean {
  return destinations.some((destination) => APPROVAL_KINDS.has(destination.kind));
}

/** A destination's messages as a reader names them, joined in the order received. */
export function messageWords(destination: NotificationDestination): string {
  return destination.messages.length === 0
    ? "Audit export"
    : destination.messages.map((message) => MESSAGE_LABELS[message]).join(", ");
}

/**
 * The delivery line under the destinations: what was delivered over the window and how fast, then
 * what was not sent and what failed. Null without an approval destination, where the card keeps
 * its own sentence.
 */
export function deliveryWords(delivery: NotificationDelivery, hasDestinations: boolean): string | null {
  if (!hasDestinations) return null;
  const days = String(delivery.window_days);
  const delivered = count(delivery.delivered, "notification");
  const said: string[] = [];
  if (delivery.delivered === 0) {
    said.push(`No notifications delivered in the last ${days} days.`);
  } else if (delivery.median_seconds !== null && delivery.p90_seconds !== null) {
    said.push(
      `Last ${days} days: ${delivered} delivered. Half arrived within ${durationWords(delivery.median_seconds)}, nine in ten within ${durationWords(delivery.p90_seconds)}.`,
    );
  } else {
    said.push(
      delivery.slowest_seconds === null
        ? `Last ${days} days: ${delivered} delivered.`
        : `Last ${days} days: ${delivered} delivered. The slowest arrived after ${durationWords(delivery.slowest_seconds)}.`,
    );
  }
  if (delivery.lapsed > 0) {
    said.push(`${String(delivery.lapsed)} not sent because the approval would have lapsed before it arrived.`);
  }
  if (delivery.failed > 0) said.push(`${String(delivery.failed)} could not be delivered.`);
  return said.join(" ");
}

/**
 * The deadline dialog's warning as the administrator types, or null (#678). Only for a value
 * the server would accept, and only where an approval destination exists. The measured rule wins
 * over the fixed email rule when both hold.
 */
export function deadlineHint(
  proposed: string,
  destinations: readonly NotificationDestination[],
  delivery: NotificationDelivery,
  bounds: { min: number; max: number } = { min: 120, max: 3600 },
): string | null {
  if (!announces(destinations)) return null;
  const typed = proposed.trim();
  if (!/^\d{1,8}$/.test(typed)) return null;
  const seconds = Number(typed);
  if (seconds < bounds.min || seconds > bounds.max) return null;
  const p90 = delivery.p90_seconds;
  if (p90 !== null && seconds < DELIVERY_MULTIPLE * p90) {
    return `Nine in ten notifications here arrived within ${durationWords(p90)} over the last ${String(delivery.window_days)} days. A deadline under ${durationWords(DELIVERY_MULTIPLE * p90)} can lapse before an approver has read the message.`;
  }
  if (seconds === 120 && destinations.some((destination) => destination.kind === "email")) {
    return "Email can arrive after a 2-minute deadline. Approvers who rely on email may not get the message in time.";
  }
  return null;
}

/** Below this many seconds, a deadline can lapse before an announcement reaches a reviewer. */
export const LAPSE_WARNING_SECONDS = 600;

/**
 * The deadline dialog's other warning, for a short deadline the delivery hint above does not cover
 * (#678): a whole number of seconds the server would accept, under ten minutes, where something
 * announces approvals. It states that a message can arrive after the request lapsed, then the
 * slowest delivery measured here when there is one, and never a cadence. Where nothing announces
 * approvals there is no message to arrive late, and the readiness card's warning covers that case.
 */
export function lapseWarning(
  proposed: string,
  destinations: readonly NotificationDestination[],
  delivery: NotificationDelivery,
  bounds: { min: number; max: number } = { min: 120, max: 3600 },
): string | null {
  if (!announces(destinations)) return null;
  const typed = proposed.trim();
  if (!/^\d{1,8}$/.test(typed)) return null;
  const seconds = Number(typed);
  if (seconds < bounds.min || seconds > bounds.max || seconds >= LAPSE_WARNING_SECONDS) return null;
  const said = [
    `Messages to reviewers can arrive after a ${durationWords(seconds)} deadline, and a request that lapses first cannot be decided.`,
  ];
  if (delivery.slowest_seconds !== null) {
    said.push(
      `In the last ${String(delivery.window_days)} days the slowest message here arrived after ${durationWords(delivery.slowest_seconds)}.`,
    );
  }
  return said.join(" ");
}
