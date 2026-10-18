// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { NotificationDelivery, NotificationDestination, TenantSettingsView } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage } from "../../test/page";
import { DeadlineDialog } from "./DeadlineDialog";

const CURRENT = { seconds: 120, bounds: { min: 120, max: 3600 }, changed: null };
const EMAIL: NotificationDestination[] = [{ destination_id: "jane", kind: "email", host: "", approvers: null, messages: ["pending"], classes: ["approvals"] }];
const MEASURED: NotificationDelivery = {
  window_days: 7,
  delivered: 8,
  median_seconds: 30,
  p90_seconds: 90,
  slowest_seconds: 140,
  lapsed: 0,
  failed: 0,
};
const UNMEASURED: NotificationDelivery = { ...MEASURED, delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null };

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

function open(destinations: NotificationDestination[], delivery: NotificationDelivery) {
  const seen = answerWith({
    "POST /api/console/v1/tenant/deadline": (request) => ({
      body: { deadline: { ...CURRENT, seconds: Number((request.body as { deadline: string }).deadline) } } as unknown as TenantSettingsView,
    }),
  });
  renderPage(<DeadlineDialog open onClose={() => undefined} current={CURRENT} destinations={destinations} delivery={delivery} />);
  return seen;
}

describe("the deadline dialog's delivery hint (#678, AY17)", () => {
  it("warns at the minimum with an email destination, in the field's description, without blocking", async () => {
    const seen = open(EMAIL, UNMEASURED);
    const user = userEvent.setup();
    const dialog = await screen.findByRole("dialog");
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    const hint = within(dialog).getByText(/^Email can arrive after a 2-minute deadline\./);
    expect(hint).toHaveClass("muted");
    expect(hint).not.toHaveAttribute("role");
    expect(field.getAttribute("aria-describedby")?.split(" ")).toContain(hint.id);
    expect(field).not.toHaveAttribute("aria-invalid");
    const confirm = within(dialog).getByRole("button", { name: "Change deadline" });
    expect(confirm).toBeEnabled();
    await user.type(within(dialog).getByRole("textbox", { name: /Reason/ }), "Faster approvals");
    await user.click(confirm);
    await vi.waitFor(() => {
      expect(seen.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
        { deadline: "120", reason: "Faster approvals" },
      ]);
    });
  });

  it("changes as the administrator types: the measured warning, then none", async () => {
    open(EMAIL, MEASURED);
    const user = userEvent.setup();
    const dialog = await screen.findByRole("dialog");
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    const measured =
      "Nine in ten notifications here arrived within 90 s over the last 7 days. A deadline under 5 min can lapse before an approver has read the message.";
    expect(within(dialog).getByText(measured)).toBeInTheDocument();
    expect(within(dialog).queryByText(/^Email can arrive/)).toBeNull();
    await user.clear(field);
    await user.type(field, "200");
    expect(within(dialog).getByText(measured)).toBeInTheDocument();
    // Past the measured rule, a deadline under ten minutes still gets the lapse warning (AR12).
    await user.clear(field);
    await user.type(field, "300");
    expect(within(dialog).queryByText(measured)).toBeNull();
    expect(within(dialog).getByText(/^Messages to reviewers can arrive after a 5 min deadline/)).toBeInTheDocument();
    for (const typed of ["600", "off", "3601", "soon"]) {
      await user.clear(field);
      await user.type(field, typed);
      expect(within(dialog).queryByText(measured)).toBeNull();
      expect(field.getAttribute("aria-describedby")).toBe(`${field.id}-hint`);
    }
  });

  it("gives no hint without an approval destination", async () => {
    open([{ destination_id: "audit", kind: "security-events", host: "siem.example.net", approvers: null, messages: [], classes: [] }], MEASURED);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByText(/Nine in ten|Email can arrive/)).toBeNull();
  });
});

describe("the deadline dialog's lapse warning (#678, AR12)", () => {
  const WEBHOOK: NotificationDestination[] = [
    { destination_id: "soc", kind: "webhook", host: "alerts.example.net", approvers: null, messages: ["pending"], classes: ["approvals"] },
  ];
  const LAPSE = /^Messages to reviewers can arrive after a .* deadline, and a request that lapses first cannot be decided\./;

  it("appears under ten minutes where something announces approvals, in the hold tone and the field's description", async () => {
    const seen = open(WEBHOOK, UNMEASURED);
    const user = userEvent.setup();
    const dialog = await screen.findByRole("dialog");
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    const warning = within(dialog).getByText("Messages to reviewers can arrive after a 2 min deadline, and a request that lapses first cannot be decided.");
    expect(warning).toHaveClass("tone-hold");
    expect(warning).not.toHaveAttribute("role");
    expect(field.getAttribute("aria-describedby")?.split(" ")).toContain(warning.id);
    for (const [typed, words] of [["599", "10 min"], ["150", "3 min"]] as const) {
      await user.clear(field);
      await user.type(field, typed);
      expect(within(dialog).getByText(`Messages to reviewers can arrive after a ${words} deadline, and a request that lapses first cannot be decided.`)).toBeInTheDocument();
    }
    for (const typed of ["600", "off", "12a", "119", "3601"]) {
      await user.clear(field);
      await user.type(field, typed);
      expect(within(dialog).queryByText(LAPSE)).toBeNull();
      expect(field.getAttribute("aria-describedby")).toBe(`${field.id}-hint`);
    }
    // Advice, not a gate: typing sent nothing, and Change deadline without a reason sends nothing.
    await user.click(within(dialog).getByRole("button", { name: "Change deadline" }));
    expect(seen).toEqual([]);
  });

  it("is absent where nothing announces approvals", async () => {
    open([{ destination_id: "audit", kind: "security-events", host: "siem.example.net", approvers: null, messages: [], classes: [] }], UNMEASURED);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("textbox", { name: /Seconds/ })).toHaveValue("120");
    expect(within(dialog).queryByText(LAPSE)).toBeNull();
  });

  it("gives way to the fixed email hint at the minimum, and follows it everywhere else under ten minutes", async () => {
    open(EMAIL, UNMEASURED);
    const user = userEvent.setup();
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/^Email can arrive after a 2-minute deadline\./)).toBeInTheDocument();
    expect(within(dialog).queryByText(LAPSE)).toBeNull();
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    await user.clear(field);
    await user.type(field, "240");
    expect(within(dialog).getByText(LAPSE)).toBeInTheDocument();
    expect(within(dialog).queryByText(/^Email can arrive/)).toBeNull();
  });

  it("adds the slowest delivery measured here, with no cadence", async () => {
    open(WEBHOOK, { ...UNMEASURED, delivered: 3, slowest_seconds: 140 });
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(
        "Messages to reviewers can arrive after a 2 min deadline, and a request that lapses first cannot be decided. In the last 7 days the slowest message here arrived after 3 min.",
      ),
    ).toBeInTheDocument();
  });
});
