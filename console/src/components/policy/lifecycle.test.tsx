// SPDX-License-Identifier: AGPL-3.0-only
// The policy stepper (#678): validate, preview, activate, in that order, with the
// preview inside it and nothing replayed until a person asks.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { client } from "../../api/client.gen";
import type { BundlePreviewView, PolicyComparison } from "../../api/types.gen";
import { createClientConfig, holdCsrfToken } from "../../lib/client-config";
import { registerStepUp } from "../../lib/step-up";
import {
  ACTIVE,
  detail,
  DRAFT,
  expectNoRequests,
  json,
  mount,
  NOT_COMPARED,
  PREVIEW,
  resetClient,
  stub,
} from "../../test/policy";
import { BundleDetailView } from "./BundleDetail";
import { compareSummary } from "./Compare";
import { DIRECTION } from "./format";

beforeEach(expectNoRequests);
afterEach(resetClient);

const validated = () => detail({ bundle_id: DRAFT, content_hash: "d".repeat(64), state: "VALIDATED", active: false });
const PREVIEWED: BundlePreviewView = { ...PREVIEW, state: "VALIDATED", window: "7d", window_seconds: 604800 };

/** Every heading of the page, in document order. */
function headings(): string[] {
  return screen.getAllByRole("heading").map((heading) => heading.textContent);
}

function steps(): HTMLElement[] {
  const stepper = screen.getByRole("list", { name: "Steps to make this policy live" });
  return within(stepper).getAllByRole("listitem").filter((item) => item.parentElement === stepper);
}

describe("the stepper", () => {
  it("sits under what the policy does, in the order validate, preview, activate", async () => {
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await screen.findByRole("heading", { name: "Make this policy live" });
    const order = headings();
    const at = (name: string) => order.indexOf(name);
    expect(at("What this policy does")).toBeGreaterThanOrEqual(0);
    expect(at("What this policy does")).toBeLessThan(at("Make this policy live"));
    expect(at("Make this policy live")).toBeLessThan(at("Changes from the active policy"));
    expect(at("Changes from the active policy")).toBeLessThan(at("Rules"));
    expect(at("Rules")).toBeLessThan(at("Limits"));
    expect(at("1. Validate")).toBeLessThan(at("2. Preview"));
    expect(at("2. Preview")).toBeLessThan(at("3. Activate"));
    // Both Advanced disclosures come last, after every card.
    const summaries = [...document.querySelectorAll("details > summary")].map((item) => item.textContent);
    expect(summaries.slice(-2)).toEqual([
      "Advanced: version identity and operation mappings",
      "Advanced: Cedar policy language",
    ]);
  });

  it("replays nothing on arrival, and offers the preview as the current step", async () => {
    const sent = vi.fn();
    stub((request) => {
      sent(request.url);
      return Promise.resolve(json(PREVIEWED));
    });
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await screen.findByRole("heading", { name: "Make this policy live" });
    expect(sent).not.toHaveBeenCalled();
    const [validate, preview, activate] = steps();
    expect(preview).toHaveAttribute("aria-current", "step");
    expect(validate).not.toHaveAttribute("aria-current");
    expect(within(validate ?? document.body).getByText("Done")).toBeInTheDocument();
    expect(within(preview ?? document.body).getByRole("button", { name: "Preview the last 7 days" })).toBeInTheDocument();
    expect(within(activate ?? document.body).getByText("Not previewed")).toBeInTheDocument();
  });

  it("follows the window chosen in the button's words and the request", async () => {
    const bodies: unknown[] = [];
    stub(async (request) => {
      bodies.push(await request.clone().json());
      return json({ ...PREVIEWED, window: "24h", window_seconds: 86400 });
    });
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.selectOptions(await screen.findByLabelText("Replay over"), "24h");
    await userEvent.click(screen.getByRole("button", { name: "Preview the last 24 hours" }));
    await waitFor(() => {
      expect(bodies).toEqual([{ window: "24h" }]);
    });
  });

  it("opens the activation dialog on the preview line, not previewed first", async () => {
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    const first = dialog.querySelector(".dialog-body > p");
    expect(first?.textContent).toBe(
      "Not previewed. Nothing here says what this policy would decide differently from the one in use.",
    );
  });

  it("states what the preview found in step 3 and opens the dialog on it", async () => {
    stub(() => Promise.resolve(json(PREVIEWED)));
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.click(await screen.findByRole("button", { name: "Preview the last 7 days" }));
    const line =
      "Previewed over the last 7 days: 1 of 3 recorded decisions would change (1 allowed to held).";
    const [, , activate] = steps();
    await waitFor(() => {
      expect(within(activate ?? document.body).getByText(line)).toBeInTheDocument();
    });
    expect(activate).toHaveAttribute("aria-current", "step");
    expect(within(activate ?? document.body).getByText("Previewed")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.querySelector(".dialog-body > p")?.textContent).toBe(line);
  });

  it("asks what changed and why, sends it, and keeps it when the server refuses it", async () => {
    const bodies: unknown[] = [];
    let refuse = true;
    stub(async (request) => {
      bodies.push(await request.clone().json());
      if (refuse) {
        refuse = false;
        return json({ code: "INVALID_BODY", detail: "x", fields: ["reason"] }, 400);
      }
      return json(detail({ bundle_id: DRAFT, state: "ACTIVE", active: true }));
    });
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Activate" });
    expect(confirm).toBeDisabled();
    const reason = within(dialog).getByLabelText(/What changed and why/);
    expect(within(dialog).getByText(/Required, up to 500 characters\. Shown on the policy list/)).toBeInTheDocument();
    await userEvent.type(reason, "Tighten tier 0");
    await userEvent.click(confirm);
    await waitFor(() => {
      expect(within(dialog).getByRole("alert")).toBeInTheDocument();
    });
    expect(reason).toHaveValue("Tighten tier 0");
    // The detail is not replaced until the server answers yes.
    expect(screen.getByText("3. Activate")).toBeInTheDocument();
    await userEvent.click(confirm);
    await waitFor(() => {
      expect(bodies).toHaveLength(2);
    });
    expect(bodies).toEqual([
      { confirm: true, reason: "Tighten tier 0" },
      { confirm: true, reason: "Tighten tier 0" },
    ]);
  });

  it("lets a Policy manager preview, and says whose decisions were counted", async () => {
    stub(() => Promise.resolve(json({ ...PREVIEWED, scope: "spaces" })));
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    expect(await screen.findByRole("button", { name: "Preview the last 7 days" })).toBeEnabled();
    expect(screen.queryByText(/requires a workspace Administrator/)).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Preview the last 7 days" }));
    expect(await screen.findByText(/Over the decisions recorded in the Spaces you manage\./)).toBeInTheDocument();
  });

  it("offers the preview on a policy active only in another Space", async () => {
    mount(
      <BundleDetailView detail={detail({ state: "ACTIVE", active: false })} active={{ bundle_id: DRAFT }} />,
      `/policy/${ACTIVE}`,
    );
    await screen.findByRole("heading", { name: "Make this policy live" });
    const [, preview] = steps();
    expect(preview).toHaveAttribute("aria-current", "step");
    expect(within(preview ?? document.body).getByRole("button", { name: "Preview the last 7 days" })).toBeInTheDocument();
  });

  it("names who activated the policy in use here, and why", async () => {
    mount(
      <BundleDetailView
        detail={detail({
          activation: {
            at: "2026-10-08T09:15:00Z",
            by_id: "55555555-5555-5555-5555-555555555555",
            by_label: null,
            by_number: 1,
            reason: "Tighten tier 0",
          },
        })}
        active={{ bundle_id: ACTIVE }}
      />,
      `/policy/${ACTIVE}`,
    );
    await screen.findByRole("heading", { name: "Make this policy live" });
    const [, , activate] = steps();
    expect(within(activate ?? document.body).getByText("Active in this Space")).toBeInTheDocument();
    expect(activate).toHaveTextContent(/Activated .+ by User 1: Tighten tier 0/);
    expect(screen.queryByRole("button", { name: /Preview the last/ })).toBeNull();
  });
});

describe("activation behind the step-up", () => {
  let withdraw: () => void = () => undefined;
  afterEach(() => {
    withdraw();
    holdCsrfToken("");
    vi.unstubAllGlobals();
  });

  it("asks for a code in place and sends the same reason again", async () => {
    const bodies: unknown[] = [];
    const transport = vi.fn(async (request: Request) => {
      if (request.url.endsWith("/compare")) return json(NOT_COMPARED);
      bodies.push(await request.clone().json());
      return bodies.length === 1
        ? new Response('{"code":"MFA_REQUIRED"}', { status: 401 })
        : json(detail({ bundle_id: DRAFT, state: "ACTIVE", active: true }));
    });
    vi.stubGlobal("fetch", transport);
    const config = createClientConfig({});
    client.setConfig({ ...config, baseUrl: "http://console.test/" });
    const prompt = vi.fn(() => Promise.resolve(true));
    withdraw = registerStepUp(prompt);
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    await userEvent.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/What changed and why/), "Tighten tier 0");
    await userEvent.click(within(dialog).getByRole("button", { name: "Activate" }));
    await waitFor(() => {
      expect(bodies).toHaveLength(2);
    });
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(bodies).toEqual([
      { confirm: true, reason: "Tighten tier 0" },
      { confirm: true, reason: "Tighten tier 0" },
    ]);
  });
});

const COMPARED: PolicyComparison = {
  ...NOT_COMPARED,
  against: ACTIVE,
  comparable: true,
  why_not: null,
  rules: [
    {
      change: "changed",
      rule_id: "note-only",
      action: "endpoint.isolate",
      before_effect: "DENY",
      after_effect: "DENY",
      before: "Deny endpoint.isolate when role is domain_controller.",
      after: "Deny endpoint.isolate when role is domain_controller.",
      fields: ["note"],
      direction: "none",
    },
    {
      change: "added",
      rule_id: "allow-more",
      action: "endpoint.isolate",
      before_effect: null,
      after_effect: "ALLOW",
      before: null,
      after: "Allow endpoint.isolate when <b>x</b>.",
      fields: [],
      direction: "wider",
    },
  ],
  budgets: [
    {
      change: "changed",
      rule_id: "tenant-total",
      before: "20 total targets per 15 minutes, then denied",
      after: "10 total targets per 15 minutes, then denied",
      fields: ["max_targets"],
      direction: "narrower",
    },
  ],
  wider: 1,
  narrower: 1,
};

describe("changes from the active policy", () => {
  it("give each direction a word before a colour", () => {
    expect(DIRECTION.wider).toEqual({ word: "Allows more", tone: "allow" });
    expect(DIRECTION.narrower?.word).toBe("Allows less");
    expect(DIRECTION.unclear?.word).toBe("Check");
    expect(DIRECTION.none).toBeNull();
  });

  it("lists what allows more first, each rule as it reads, with no markup", async () => {
    stub(() => Promise.reject(new Error("unexpected request")), COMPARED);
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    const card = (await screen.findByRole("heading", { name: "Changes from the active policy" })).closest("section");
    if (card === null) throw new Error("the card is a section");
    await within(card).findByText(/compared with Policy version 11111111, the policy active in this Space/);
    const items = within(card).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    const [first, second, third] = items;
    expect(within(first ?? card).getByText("Allows more")).toHaveClass("badge-allow");
    expect(within(first ?? card).getByText("allow-more")).toHaveClass("mono");
    expect(within(first ?? card).getByText("After: Allow isolating an endpoint when <b>x</b>.")).toBeInTheDocument();
    expect(card.querySelector("b")).toBeNull();
    expect(within(second ?? card).getByText("Allows less")).toBeInTheDocument();
    expect(within(second ?? card).getByText("Before: 20 total targets per 15 minutes, then denied")).toBeInTheDocument();
    expect(within(third ?? card).queryByText(/Allows|Check/)).toBeNull();
    expect(within(third ?? card).getByText("Only its note changes.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText("Compared with Policy version 11111111 as the rules read: 1 change allows more, 1 allows less."),
    ).toBeInTheDocument();
  });

  it("says a draft that only maps another account allows more", async () => {
    const mapped: PolicyComparison = {
      ...NOT_COMPARED,
      against: ACTIVE,
      comparable: true,
      why_not: null,
      mappings: [
        {
          change: "added",
          action: "endpoint.isolate",
          operation_ref: "isolate.second",
          account_id: "66666666-6666-6666-6666-666666666666",
          fields: [],
          direction: "wider",
        },
      ],
      wider: 1,
    };
    stub(() => Promise.reject(new Error("unexpected request")), mapped);
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    expect(await screen.findByText("endpoint.isolate is also served through another connector account")).toBeInTheDocument();
    expect(screen.getByText("66666666-6666-6666-6666-666666666666")).toHaveClass("mono");
    expect(screen.getAllByText("Allows more")).toHaveLength(1);
    expect(screen.queryByText(/are the same as the policy in use/)).toBeNull();
  });

  it.each([
    ["no-active", "No policy is active in this Space, so every rule here is new."],
    ["no-space", "Choose a Space to compare this policy with the one it would replace."],
    ["cedar", /written in Cedar rather than as rules, so it cannot be compared rule by rule/],
  ] as const)("says why it cannot compare (%s)", async (whyNot, sentence) => {
    stub(() => Promise.reject(new Error("unexpected request")), { ...NOT_COMPARED, why_not: whyNot });
    mount(<BundleDetailView detail={validated()} active={{ bundle_id: ACTIVE }} />, `/policy/${DRAFT}`);
    expect(await screen.findByText(sentence)).toBeInTheDocument();
  });

  it("is not shown for the policy in use here", async () => {
    mount(<BundleDetailView detail={detail()} active={{ bundle_id: ACTIVE }} />, `/policy/${ACTIVE}`);
    await screen.findByRole("heading", { name: "Make this policy live" });
    expect(screen.queryByRole("heading", { name: "Changes from the active policy" })).toBeNull();
  });

  it("counts by direction for the activation dialog", () => {
    expect(compareSummary(undefined)).toBeNull();
    expect(compareSummary(NOT_COMPARED)).toBeNull();
    expect(compareSummary({ ...COMPARED, wider: 2, narrower: 0, unclear: 1 })).toBe(
      "Compared with Policy version 11111111 as the rules read: 2 changes allow more, 1 to check.",
    );
    expect(compareSummary({ ...COMPARED, wider: 0, narrower: 0, unclear: 0 })).toBe(
      "Compared with Policy version 11111111 as the rules read: nothing allows more or less.",
    );
  });
});
