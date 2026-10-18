// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import type { NotificationDelivery, NotificationDestination } from "../../api/types.gen";
import { DELIVERY_MULTIPLE, deadlineHint, deliveryWords, durationWords, MESSAGE_LABELS, messageWords } from "./delivery";

function delivery(changes: Partial<NotificationDelivery> = {}): NotificationDelivery {
  return {
    window_days: 7,
    delivered: 6,
    median_seconds: 40,
    p90_seconds: 70,
    slowest_seconds: 95,
    lapsed: 0,
    failed: 0,
    ...changes,
  };
}

function destination(kind: string, messages: NotificationDestination["messages"] = ["pending"]): NotificationDestination {
  return { destination_id: kind, kind, host: "", approvers: null, messages };
}

const WEBHOOK = [destination("webhook")];
const EMAIL = [destination("email")];
const AUDIT_EXPORT = destination("security-events", []);
const AUDIT = [AUDIT_EXPORT];
const NONE = delivery({ delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null });

describe("the delivery words", () => {
  it("rounds a duration up to whole minutes from two minutes", () => {
    expect(durationWords(59)).toBe("59 s");
    expect(durationWords(119)).toBe("119 s");
    expect(durationWords(120)).toBe("2 min");
    expect(durationWords(270)).toBe("5 min");
  });

  it("names each message, in the order the server sends them", () => {
    expect(MESSAGE_LABELS).toEqual({ pending: "New requests", reminder: "Reminders", closed: "Outcomes" });
    expect(messageWords(destination("webhook", ["pending", "closed"]))).toBe("New requests, Outcomes");
    expect(messageWords(destination("slack", ["reminder"]))).toBe("Reminders");
    expect(messageWords(AUDIT_EXPORT)).toBe("Audit export");
  });

  it("gives the median and the 90th percentile from five deliveries", () => {
    expect(deliveryWords(delivery(), true)).toBe(
      "Last 7 days: 6 notifications delivered. Half arrived within 40 s, nine in ten within 70 s.",
    );
  });

  it("gives the slowest below five deliveries", () => {
    expect(deliveryWords(delivery({ delivered: 1, median_seconds: null, p90_seconds: null, slowest_seconds: 130 }), true)).toBe(
      "Last 7 days: 1 notification delivered. The slowest arrived after 3 min.",
    );
    expect(deliveryWords(delivery({ delivered: 4, median_seconds: null, p90_seconds: null, slowest_seconds: 12 }), true)).toBe(
      "Last 7 days: 4 notifications delivered. The slowest arrived after 12 s.",
    );
  });

  it("says when nothing was delivered, and adds what lapsed and what failed", () => {
    expect(deliveryWords(NONE, true)).toBe("No notifications delivered in the last 7 days.");
    expect(deliveryWords({ ...NONE, lapsed: 2, failed: 1 }, true)).toBe(
      "No notifications delivered in the last 7 days. 2 not sent because the approval would have lapsed before it arrived. 1 could not be delivered.",
    );
    expect(deliveryWords(delivery({ failed: 3 }), true)).toMatch(/nine in ten within 70 s\. 3 could not be delivered\.$/);
  });

  it("says nothing without an approval destination", () => {
    expect(deliveryWords(delivery(), false)).toBeNull();
  });
});

describe("the deadline hint", () => {
  const measured =
    "Nine in ten notifications here arrived within 90 s over the last 7 days. A deadline under 5 min can lapse before an approver has read the message.";
  const fixed = "Email can arrive after a 2-minute deadline. Approvers who rely on email may not get the message in time.";

  it("warns at the minimum with an email destination and no measurement", () => {
    expect(deadlineHint("120", EMAIL, NONE)).toBe(fixed);
    expect(deadlineHint(" 120 ", [...WEBHOOK, ...EMAIL], NONE)).toBe(fixed);
    expect(deadlineHint("120", WEBHOOK, NONE)).toBeNull();
    expect(deadlineHint("121", EMAIL, NONE)).toBeNull();
  });

  it("warns under three times the measured 90th percentile, and that warning alone", () => {
    const p90 = delivery({ p90_seconds: 90 });
    expect(DELIVERY_MULTIPLE).toBe(3);
    expect(deadlineHint("200", WEBHOOK, p90)).toBe(measured);
    expect(deadlineHint("120", EMAIL, p90)).toBe(measured);
    expect(deadlineHint("269", WEBHOOK, p90)).toBe(measured);
    expect(deadlineHint("270", WEBHOOK, p90)).toBeNull();
    expect(deadlineHint("300", EMAIL, p90)).toBeNull();
  });

  it("gives no hint for a value the server would refuse, or without an approval destination", () => {
    const p90 = delivery({ p90_seconds: 90 });
    for (const typed of ["off", "3601", "119", "abc", "", "1e2", "-150"]) {
      expect(deadlineHint(typed, EMAIL, p90)).toBeNull();
    }
    expect(deadlineHint("200", [], p90)).toBeNull();
    expect(deadlineHint("120", AUDIT, p90)).toBeNull();
  });
});
