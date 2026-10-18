// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApprovalCoverage, ApproversPage, CoverageAction, SampleStatusView } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage, settle, type Answer, type Seen } from "../../test/page";
import { SETUP, SPACE, setupView } from "../../test/setup-view";
import { ReviewCoverage } from "./ReviewCoverage";
import { WelcomePage } from "./WelcomePage";

const ELSEWHERE = "77777777-7777-4777-8777-777777777777";
const ME = "33333333-3333-4333-8333-333333333333";
const DANA = "55555555-5555-4555-8555-555555555555";
const TARGET = "44444444-4444-4444-8444-444444444444";
const GAP = "88888888-8888-4888-8888-888888888888";
const NOW = "2026-10-11T12:00:00Z";
const COVERAGE = "/api/console/v1/approval-coverage";
const APPROVERS = "/api/console/v1/approvers";
const ASSIGN = "/api/console/v1/approvers/assign";

const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  mode: "ENFORCE",
  permissions: ["console.read", "access.manage", "policy.manage", "approvals.decide"],
  person: { label: "Avery Admin", detail: "", initials: "AA", id: ME },
};
const POLICY_MANAGER: SessionSummary = { ...ADMIN, role: "POLICY_MANAGER", permissions: ["console.read", "policy.manage"] };

const EMPTY = { total: 0, rows: [] };

function action(changes: Partial<CoverageAction> = {}): CoverageAction {
  return {
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    held_by: ["rule:prod-review"],
    known: true,
    required: 1,
    upto: null,
    reviewers: 0,
    held_uncovered: {
      total: 1,
      rows: [{ canonical_target_id: GAP, labels: "server-gap.corp.example", requests: 2, last_requested_at: NOW, reviewers: 0 }],
    },
    requested_uncovered: EMPTY,
    thin: EMPTY,
    ...changes,
  };
}

function coverage(actions: CoverageAction[], changes: Partial<ApprovalCoverage> = {}): ApprovalCoverage {
  return {
    server_time: NOW,
    since: "2026-09-11T12:00:00Z",
    mode: "ENFORCE",
    truncated: false,
    // Another Space first, so only matching this Space's id finds this Space's actions.
    spaces: [
      {
        space_id: ELSEWHERE,
        name: "Elsewhere",
        bundle_id: null,
        policy: "rules",
        actions: [action({ action: "identity.disable", action_label: "Disable user account" })],
      },
      { space_id: SPACE, name: "Default", bundle_id: null, policy: "rules", actions },
    ],
    ...changes,
  };
}

function scopes(approvers: ApproversPage["approvers"]): ApproversPage {
  return {
    assignments: [],
    approvers,
    actions: ["endpoint.isolate", "endpoint.lift_isolation", "identity.disable"],
    targets: [{ canonical_target_id: TARGET, labels: "server-a.corp.example" }],
  };
}

const BOTH = scopes([
  { principal_id: DANA, label: "Dana Reyes", email: "dana@example.com", number: 2 },
  { principal_id: ME, label: "Avery Admin", email: "avery@example.com", number: 1 },
]);

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

function answer(read: ApprovalCoverage, approvers: ApproversPage = BOTH, routes: Record<string, Answer> = {}): Seen[] {
  return answerWith({
    [`GET ${COVERAGE}`]: { body: read },
    [`GET ${APPROVERS}`]: { body: approvers },
    ...routes,
  });
}

function reads(seen: Seen[], path: string): number {
  return seen.filter((call) => call.method === "GET" && call.path === path).length;
}

function writes(seen: Seen[]): Seen[] {
  return seen.filter((call) => call.method !== "GET");
}

async function list(): Promise<HTMLElement> {
  return screen.findByRole("region", { name: "Actions nobody in this Space can review" });
}

describe("which actions nobody can review (UX19, #678)", () => {
  it("lists each action in this Space with no eligible reviewer by its catalog words, and no target or reviewer", async () => {
    answer(
      coverage([
        action(),
        action({ action: "endpoint.lift_isolation", action_label: "Lift isolation", reviewers: 2, held_uncovered: EMPTY }),
      ]),
    );
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    const rows = within(found).getAllByRole("listitem");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Isolate endpoint");
    // Covered actions and other Spaces' actions are not this Space's gaps.
    expect(found).not.toHaveTextContent("Lift isolation");
    expect(found).not.toHaveTextContent("Disable user account");
    // Never a target, a hostname or a reviewer's identity.
    for (const text of ["server-gap", "corp.example", "8888", "server-a", "Dana", "dana@example.com", "Avery"]) {
      expect(found).not.toHaveTextContent(text);
    }
  });

  it("shows nothing when every action this Space's policy holds has a reviewer", async () => {
    const seen = answer(coverage([action({ reviewers: 1, held_uncovered: EMPTY })]));
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    await waitFor(() => {
      expect(reads(seen, COVERAGE)).toBe(1);
    });
    await settle();
    expect(screen.queryByRole("region", { name: "Actions nobody in this Space can review" })).toBeNull();
  });

  it("opens the prefilled assignment dialog from Add a reviewer and sends nothing until it is confirmed", async () => {
    const seen = answer(coverage([action()]), BOTH, { [`POST ${ASSIGN}`]: { body: BOTH } });
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    await userEvent.click(await within(found).findByRole("button", { name: "Add a reviewer for Isolate endpoint" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    expect(within(dialog).getByLabelText("Action")).toHaveValue("endpoint.isolate");
    expect(within(dialog).getByLabelText("Approver")).toHaveValue(DANA);
    await settle();
    expect(writes(seen)).toEqual([]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    await waitFor(() => {
      expect(writes(seen)).toHaveLength(1);
    });
    expect(writes(seen)[0]).toMatchObject({ method: "POST", path: ASSIGN, body: { approver: DANA, target: TARGET, action: "endpoint.isolate" } });
  });

  it("closing the dialog without confirming assigns nobody", async () => {
    const seen = answer(coverage([action()]));
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    await userEvent.click(await within(found).findByRole("button", { name: "Add a reviewer for Isolate endpoint" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Assign an approver" })).toBeNull();
    });
    expect(writes(seen)).toEqual([]);
  });

  it("opens the same dialog prefilled with the administrator from Assign me", async () => {
    const seen = answer(coverage([action()]), BOTH, { [`POST ${ASSIGN}`]: { body: BOTH } });
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    await userEvent.click(await within(found).findByRole("button", { name: "Assign me to review Isolate endpoint" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    expect(within(dialog).getByLabelText("Approver")).toHaveValue(ME);
    expect(within(dialog).getByLabelText("Action")).toHaveValue("endpoint.isolate");
    expect(writes(seen)).toEqual([]);
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    await waitFor(() => {
      expect(writes(seen)).toHaveLength(1);
    });
    expect(writes(seen)[0]).toMatchObject({ path: ASSIGN, body: { approver: ME, action: "endpoint.isolate" } });
  });

  it("offers Assign me only where the administrator may hold the scope", async () => {
    answer(coverage([action()]), scopes([{ principal_id: DANA, label: "Dana Reyes", email: null, number: 2 }]));
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    expect(await within(found).findByRole("button", { name: "Add a reviewer for Isolate endpoint" })).toBeInTheDocument();
    expect(within(found).queryByRole("button", { name: /Assign me/ })).toBeNull();
  });

  it("says coverage is unknown for a custom policy and offers no fix", async () => {
    const custom = action({ known: false, held_by: ["policy"], upto: 2, held_uncovered: EMPTY });
    answer(coverage([], { spaces: [{ space_id: SPACE, name: "Default", bundle_id: null, policy: "custom", actions: [custom] }] }));
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    expect(found).toHaveTextContent("Isolate endpoint");
    expect(found).toHaveTextContent("Coverage unknown for this policy");
    await settle();
    expect(within(found).queryByRole("button")).toBeNull();
  });

  it("renders an action label containing markup as text", async () => {
    answer(coverage([action({ action_label: "<img src=x onerror=alert(1)>Isolate" })]));
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    const found = await list();
    expect(found).toHaveTextContent("<img src=x onerror=alert(1)>Isolate");
    expect(found.querySelector("img")).toBeNull();
  });

  it("asks nothing without access.manage", async () => {
    const seen = answer(coverage([action()]));
    renderPage(<ReviewCoverage spaceId={SPACE} />, POLICY_MANAGER);
    await settle();
    expect(reads(seen, COVERAGE)).toBe(0);
    expect(reads(seen, APPROVERS)).toBe(0);
    expect(screen.queryByRole("region", { name: "Actions nobody in this Space can review" })).toBeNull();
  });

  it("shows nothing more when the coverage read is refused", async () => {
    answerWith({ [`GET ${COVERAGE}`]: { status: 403, body: { code: "FORBIDDEN", detail: "Forbidden." } } });
    renderPage(<ReviewCoverage spaceId={SPACE} />, ADMIN);
    await settle();
    expect(screen.queryByRole("region", { name: "Actions nobody in this Space can review" })).toBeNull();
  });
});

describe("the Choose who can review card (UX19, #678)", () => {
  const ABSENT: SampleStatusView = {
    state: "absent",
    offered: false,
    available: true,
    demo_available: false,
    demo_needs_refresh: false,
    bundle_id: null,
    hosts: [],
    observed_at: null,
    stale_at: null,
    first_request: null,
  };

  async function controls(session: SessionSummary): Promise<{ seen: Seen[]; card: HTMLElement }> {
    const seen = answerWith({
      "GET /api/console/v1/samples": { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView({ policy: "done" }) },
      [`GET ${COVERAGE}`]: { body: coverage([action()]) },
      [`GET ${APPROVERS}`]: { body: BOTH },
    });
    renderPage(<WelcomePage step="controls" onStep={() => undefined} />, session);
    const heading = await screen.findByRole("heading", { name: "Choose who can review" });
    const card = heading.closest("section");
    if (card === null) throw new Error("No review card");
    return { seen, card };
  }

  it("lists the actions under the milestone sentence for an administrator", async () => {
    const { card } = await controls(ADMIN);
    expect(card).toHaveTextContent("Nobody in this Space can review the actions your policy holds yet.");
    const found = await within(card).findByRole("region", { name: "Actions nobody in this Space can review" });
    expect(found).toHaveTextContent("Isolate endpoint");
  });

  it("shows only the milestone sentence, and asks nothing, without access.manage", async () => {
    const { seen, card } = await controls(POLICY_MANAGER);
    expect(card).toHaveTextContent("Nobody in this Space can review the actions your policy holds yet.");
    await settle();
    expect(reads(seen, COVERAGE)).toBe(0);
    expect(within(card).queryByRole("region", { name: "Actions nobody in this Space can review" })).toBeNull();
  });
});
