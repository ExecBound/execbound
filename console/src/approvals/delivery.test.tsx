// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ApprovalDelivery } from "../api/types.gen";
import { LAPSED_BEFORE_DECISION, lapseNotice, refusalText, statusNotice } from "./copy";
import { deliveryWord, lateLapse } from "./delivery";
import { DeliveryLine, deliveryLine } from "./DeliveryLine";
import { DetailView } from "./DetailView";
import { ADMIN, APPROVAL, APPROVER, detail, gateway, item, list, OTHER, routed } from "./fixtures";
import { renderPage } from "../test/page";

const NOW = Date.parse("2026-09-19T14:10:00Z");
const AT = "2026-09-19T14:08:31Z";

function delivery(changes: Partial<ApprovalDelivery> = {}): ApprovalDelivery {
  return {
    delivered: 0,
    pending: 0,
    failed: 0,
    lapsed: 0,
    closed: 0,
    withdrawn: 0,
    last_delivered_at: null,
    margin_seconds: null,
    late: false,
    ...changes,
  };
}

function words(sentences: ReturnType<typeof deliveryLine>): string[] {
  return sentences.map((sentence) => `${sentence.lead}${sentence.at !== undefined ? "<time>" : ""}${sentence.rest ?? ""}`);
}

function desktop() {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the delivery line (#678)", () => {
  it("says nobody was notified where no message was ever queued", () => {
    expect(words(deliveryLine(null, true))).toEqual(["Nobody was notified outside this console."]);
  });

  it("says when one message arrived, before or after the deadline", () => {
    const early = deliveryLine(delivery({ delivered: 1, last_delivered_at: AT, margin_seconds: 40 }), true);
    expect(words(early)).toEqual(["Notification delivered <time>, 40 s before the deadline."]);
    expect(early[0]?.at).toBe(AT);
    const late = deliveryLine(delivery({ delivered: 1, last_delivered_at: AT, margin_seconds: -390, late: true }), false);
    expect(words(late)).toEqual(["Notification delivered <time>, 6 min after the deadline."]);
  });

  it("says how many of several destinations were reached, and when the last was", () => {
    const several = deliveryLine(delivery({ delivered: 2, failed: 1, last_delivered_at: AT, margin_seconds: 600 }), true);
    expect(words(several)).toEqual(["Delivered to 2 of 3 destinations, the last 10 min before the deadline.", "1 could not be delivered."]);
  });

  it("tells a lapsed, a decided and a withdrawn message apart", () => {
    expect(words(deliveryLine(delivery({ lapsed: 1, late: true }), false))).toEqual(["Not sent: the approval lapsed before delivery."]);
    expect(words(deliveryLine(delivery({ closed: 1 }), false))).toEqual(["Not sent: decided before delivery."]);
    expect(words(deliveryLine(delivery({ withdrawn: 1 }), false))).toEqual(["Not sent: the request was no longer valid."]);
  });

  it("says a message is on its way only while the approval waits", () => {
    expect(words(deliveryLine(delivery({ pending: 2 }), true))).toEqual(["Sending to 2 destinations."]);
    expect(words(deliveryLine(delivery({ pending: 1 }), true))).toEqual(["Sending to 1 destination."]);
    expect(words(deliveryLine(delivery({ pending: 1 }), false))).toEqual([]);
  });

  it("says how many could not be delivered", () => {
    expect(words(deliveryLine(delivery({ failed: 2 }), true))).toEqual(["2 could not be delivered."]);
  });

  it("prints the delivery time in the console's one form", () => {
    render(<DeliveryLine item={item({ delivery: delivery({ delivered: 1, last_delivered_at: AT, margin_seconds: 40 }) })} />);
    const line = screen.getByText(/Notification delivered/);
    expect(line).toHaveTextContent(/^Notification delivered .+, 40 s before the deadline\.$/);
    expect(within(line).getByText((_, element) => element?.tagName === "TIME")).toHaveAttribute("dateTime", AT);
  });

  it("gives a row waiting on others one word", () => {
    expect(deliveryWord(null)).toBeNull();
    expect(deliveryWord(delivery({ delivered: 1, failed: 1 }))).toBe("Delivered");
    expect(deliveryWord(delivery({ pending: 1 }))).toBe("Sending");
    expect(deliveryWord(delivery({ lapsed: 1 }))).toBe("Not sent");
    expect(deliveryWord(delivery({ failed: 1 }))).toBe("Not sent");
  });

  it("flags a late lapse only on the approval deadline's clock", () => {
    expect(lateLapse(item({ delivery: delivery({ lapsed: 1, late: true }) }))).toBe(true);
    expect(lateLapse(item({ delivery: delivery({ lapsed: 1, late: true }), deadline_clock: "context validity" }))).toBe(false);
    expect(lateLapse(item({ delivery: delivery({ failed: 1 }) }))).toBe(false);
    expect(lateLapse(item())).toBe(false);
  });
});

describe("what a lapsed approval says (#678)", () => {
  const expired = (recorded: number, required: number, execution_state = "STALE_AUTHORIZATION") =>
    detail({
      status: "expired",
      item: item({ approval_state: "EXPIRED", execution_state, recorded, required }),
      quorum: { required, recorded, decisions: [], mine: recorded > 0 ? "APPROVE" : null },
    });

  it("tells an approver which of its three histories it had, that nothing ran, and to ask the agent", () => {
    expect(statusNotice(expired(0, 1))?.text).toBe(
      "This approval lapsed before anyone decided it. Nothing ran. If the agent still needs this, it must send the request again.",
    );
    expect(statusNotice(expired(1, 2))?.text).toBe(
      "This approval lapsed before enough people approved it. Nothing ran. If the agent still needs this, it must send the request again.",
    );
    expect(statusNotice(expired(1, 1))?.text).toBe(
      "This approval was approved but lapsed before the agent used it. Nothing ran. If the agent still needs this, it must send the request again.",
    );
    expect(lapseNotice(expired(0, 1, "PENDING_APPROVAL"))).toContain("Nothing ran.");
  });

  it("never says nothing ran where the execution's effect is not known", () => {
    const uncertain = expired(1, 1, "INDETERMINATE");
    expect(statusNotice(uncertain)?.text).toBe(
      "This approval was approved but lapsed before the agent used it. If the agent still needs this, it must send the request again.",
    );
    const touched = { ...expired(1, 1), timeline: [{ at: AT, kind: "transition" as const, state: "DISPATCH_COMMITTED", sentence: "", actor: null }] };
    expect(statusNotice(touched)?.text).not.toContain("Nothing ran");
  });

  it("keeps the execution-history advice for an administrator", () => {
    expect(statusNotice(expired(0, 1), true)?.text).toBe(
      "This approval lapsed and cannot be used. Review the execution history before asking the agent for a fresh plan.",
    );
  });

  it("splits a refused decision the same way", () => {
    expect(refusalText({ code: "APPROVAL_EXPIRED" })).toBe(LAPSED_BEFORE_DECISION);
    expect(LAPSED_BEFORE_DECISION).toBe(
      "This approval lapsed before your decision reached it. Nothing ran. If the agent still needs this, it must send the request again.",
    );
    expect(refusalText({ code: "APPROVAL_EXPIRED" }, true)).toContain("review its execution history");
    expect(refusalText({ code: "STOPPED" })).toBe(refusalText({ code: "STOPPED" }, true));
  });

  it("puts the delivery line on the detail for every reader", async () => {
    renderPage(
      <DetailView
        detail={expired(0, 1)}
        now={NOW}
        phone={false}
        deciding={false}
        onDecide={vi.fn()}
      />,
      APPROVER,
    );
    expect(await screen.findByText("This approval lapsed before anyone decided it. Nothing ran. If the agent still needs this, it must send the request again.")).toBeInTheDocument();
    expect(await screen.findByText("Nobody was notified outside this console.")).toBeInTheDocument();
  });
});

describe("late lapses in an administrator's Lapsed view (#678)", () => {
  beforeEach(desktop);

  const lapsed = () =>
    list([
      item({ approval_state: "EXPIRED", delivery: delivery({ delivered: 1, last_delivered_at: AT, margin_seconds: 12, late: true }) }),
      item({ approval_id: OTHER, approval_state: "EXPIRED", delivery: delivery({ failed: 1 }) }),
      item({
        approval_id: "4b1e90c2-0000-4000-8000-00000000000c",
        approval_state: "EXPIRED",
        deadline_clock: "context validity",
        delivery: delivery({ lapsed: 1, late: true }),
      }),
    ]);

  it("flags each late row on the deadline's clock and links to the setting", async () => {
    gateway({ "GET /api/console/v1/approvals": list([]), "GET /api/console/v1/approvals?view=lapsed": lapsed() });
    routed("/approvals?view=lapsed", ADMIN);
    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent(
      "1 of these lapsed with the message delivered within 30 seconds of the deadline, after it, or lapsed before it was sent. A longer approval deadline gives people time to answer.",
    );
    expect(within(note).getByRole("link", { name: "Change it in Workspace settings." })).toHaveAttribute("href", "/tenant");
    expect(screen.getAllByText("Message late")).toHaveLength(1);
    const flagged = screen.getAllByRole("link", { name: /Isolate endpoint/ }).find((row) => row.getAttribute("href")?.includes(APPROVAL));
    expect(flagged).toHaveTextContent("Message late");
  });

  it("names who can change the deadline where this administrator cannot", async () => {
    gateway({ "GET /api/console/v1/approvals": list([]), "GET /api/console/v1/approvals?view=lapsed": lapsed() });
    routed("/approvals?view=lapsed", { ...ADMIN, permissions: ["console.read", "access.manage", "approvals.decide"] });
    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent(/A workspace administrator can change the approval deadline\.$/);
    expect(within(note).queryByRole("link")).toBeNull();
  });

  it("is never shown to an approver, whose note says the agent must ask again", async () => {
    gateway({ "GET /api/console/v1/approvals": list([]), "GET /api/console/v1/approvals?view=lapsed": lapsed() });
    routed("/approvals?view=lapsed", APPROVER);
    expect(await screen.findAllByRole("link", { name: /Isolate endpoint/ })).toHaveLength(3);
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.queryByText("Message late")).toBeNull();
    expect(screen.getByText(/If the agent still needs one, it must send the request again\./)).toBeInTheDocument();
    expect(screen.queryByText(/execution history/)).toBeNull();
  });
});

describe("delivery while a request waits on others (#678)", () => {
  beforeEach(desktop);

  it("gives each row its word", async () => {
    const waiting = { reviewers: 1, reviewers_left: 1, assigned_to_you: false };
    gateway({
      "GET /api/console/v1/approvals": list([]),
      "GET /api/console/v1/approvals?view=others": list([
        item({ ...waiting, delivery: delivery({ delivered: 1, last_delivered_at: AT, margin_seconds: 600 }) }),
        item({ ...waiting, approval_id: OTHER, delivery: delivery({ pending: 1 }) }),
        item({ ...waiting, approval_id: "4b1e90c2-0000-4000-8000-00000000000d", delivery: delivery({ failed: 1 }) }),
      ]),
    });
    routed("/approvals?view=others", ADMIN);
    const said = (text: string) => (_: string, element: Element | null) => element?.tagName === "SMALL" && element.textContent === text;
    expect(await screen.findByText(said("0 of 1 approvals · 1 assigned · Delivered"))).toBeInTheDocument();
    expect(screen.getByText(said("0 of 1 approvals · 1 assigned · Sending"))).toBeInTheDocument();
    expect(screen.getByText(said("0 of 1 approvals · 1 assigned · Not sent"))).toBeInTheDocument();
  });

  it("puts the delivery line in the Waiting panel", async () => {
    const waiting = detail({
      reviewing: false,
      continuation: null,
      item: item({ reviewers: 1, reviewers_left: 1, assigned_to_you: false, delivery: delivery({ pending: 1 }) }),
    });
    renderPage(<DetailView detail={waiting} now={NOW} phone={false} deciding={false} onDecide={vi.fn()} />, ADMIN);
    const panel = await screen.findByRole("region", { name: "You are not assigned to decide this request." });
    expect(within(panel).getByText("Sending to 1 destination.")).toBeInTheDocument();
  });
});
