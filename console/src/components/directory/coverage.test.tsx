// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  AccessPage,
  ApprovalCoverage,
  ApprovalRule,
  ApprovalRulesPage,
  ApproversPage,
  CoverageAction,
  CoverageTarget,
} from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage, type Answer, type Seen } from "../../test/page";
import { ApprovalRules } from "./ApprovalRules";

const GROUP = "11111111-1111-1111-1111-111111111111";
const SPACE = "22222222-2222-2222-2222-222222222222";
const ELSEWHERE = "77777777-7777-7777-7777-777777777777";
const USER = "33333333-3333-3333-3333-333333333333";
const TARGET = "44444444-4444-4444-4444-444444444444";
const GAP = "88888888-8888-8888-8888-888888888888";
const RULE = "66666666-6666-6666-6666-666666666666";
const FULL = "99999999-9999-9999-9999-999999999999";
const NOW = "2026-10-11T12:00:00Z";

const ACCESS: AccessPage = {
  roles: [{ id: "approver", name: "Approver", description: "Review assigned requests", permissions: ["approvals.decide"], scopes: ["WORKSPACE", "SPACE"] }],
  users: [{ principal_id: USER, label: "Dana Reyes", email: null, number: 2, kind: "HUMAN_APPROVER", active: true, managed: true, direct_roles: [], inherited_roles: [] }],
  groups: [{ group_id: GROUP, name: "SOC reviewers", description: null, members: [USER], roles: [{ role: "approver", space_id: null }] }],
  spaces: [{ space_id: SPACE, name: "Default" }],
};
const SCOPES: ApproversPage = {
  assignments: [],
  approvers: [{ principal_id: USER, label: "Dana Reyes", email: null, number: 2 }],
  actions: ["endpoint.isolate", "endpoint.lift_isolation"],
  targets: [{ canonical_target_id: TARGET, labels: "server-a" }],
};
const EXISTING: ApprovalRule = {
  rule_id: RULE, name: "Endpoint response", active: true, eligible_reviewers: 1,
  group_id: GROUP, group_name: "SOC reviewers", space_id: SPACE, space_name: "Default",
  actions: ["endpoint.isolate"], targets: [TARGET],
};
const RULES: ApprovalRulesPage = {
  rules: [
    EXISTING,
    { ...EXISTING, rule_id: FULL, name: "Full rule", targets: Array.from({ length: 100 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`) },
    { ...EXISTING, rule_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", name: "Disabled rule", active: false },
    { ...EXISTING, rule_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", name: "Other action", actions: ["endpoint.lift_isolation"] },
  ],
  actions: [{ id: "endpoint.isolate", name: "Isolate endpoint" }, { id: "endpoint.lift_isolation", name: "Lift isolation" }],
};

function gap(id: string, labels: string | null, reviewers = 0, requests = 3): CoverageTarget {
  return { canonical_target_id: id, labels, requests, last_requested_at: NOW, reviewers };
}

const EMPTY = { total: 0, rows: [] };

function action(changes: Partial<CoverageAction> = {}): CoverageAction {
  return {
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    held_by: ["rule:prod-review", "limit:isolations-per-day"],
    known: true,
    required: 1,
    upto: null,
    reviewers: 3,
    held_uncovered: EMPTY,
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
    spaces: [{ space_id: SPACE, name: "Default", bundle_id: RULE, policy: "rules", actions }],
    ...changes,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  clearToasts();
});

function setup(answer: ApprovalCoverage | Answer, routes: Record<string, Answer> = {}): Seen[] {
  return answerWith({
    "GET /api/console/v1/access": { body: ACCESS },
    "GET /api/console/v1/approval-rules": { body: RULES },
    "GET /api/console/v1/approvers": { body: SCOPES },
    "GET /api/console/v1/approval-coverage": "body" in answer || typeof answer === "function" ? (answer) : { body: answer },
    ...routes,
  });
}

function reads(seen: Seen[]): number {
  return seen.filter((call) => call.method === "GET" && call.path === "/api/console/v1/approval-coverage").length;
}

async function card(): Promise<HTMLElement> {
  const heading = await screen.findByRole("heading", { name: "Decision coverage" });
  const found = heading.closest("section");
  if (found === null) throw new Error("No coverage card");
  await within(found).findByRole("heading", { name: "Default" });
  return found;
}

describe("decision coverage", () => {
  it("renders one section per Space and one row per action, with the shortfall in words", async () => {
    setup(coverage([
      action({ reviewers: 0 }),
      action({ action: "endpoint.lift_isolation", action_label: "Lift isolation", required: 2, reviewers: 1 }),
    ]));
    renderPage(<ApprovalRules />);
    const found = await card();
    expect(found.id).toBe("coverage");
    expect(found).toHaveTextContent("Nobody can decide this action in Default.");
    expect(found).toHaveTextContent("Needs 2 people; 1 can decide this action in Default.");
    expect(found).toHaveTextContent("held by rule prod-review and limit isolations-per-day");
  });

  it("says a custom policy's hold cannot be read from it", async () => {
    setup(coverage([action({ known: false, held_by: ["policy"], upto: 2 })], {
      spaces: [{ space_id: SPACE, name: "Default", bundle_id: RULE, policy: "custom", actions: [action({ known: false, held_by: ["policy"], upto: 2 })] }],
    }));
    renderPage(<ApprovalRules />);
    const found = await card();
    expect(found).toHaveTextContent("Custom policy: it may hold this action; which requests it holds cannot be read from the policy.");
    expect(found).toHaveTextContent("It may need up to 2 people.");
  });

  it("shows a gap's labels as text, its prefix, its time and its shortfall", async () => {
    setup(coverage([action({ held_uncovered: { total: 1, rows: [gap(GAP, "<img src=x onerror=alert(1)>")] } })]));
    renderPage(<ApprovalRules />);
    const found = await card();
    expect(found).toHaveTextContent("1 resource requested in the last 30 days cannot be decided.");
    expect(found).toHaveTextContent("<img src=x onerror=alert(1)>");
    expect(found.querySelector("img")).toBeNull();
    expect(found).toHaveTextContent("88888888");
    expect(found).toHaveTextContent("held 3 times, last");
    expect(found.querySelector("time")).not.toBeNull();
    expect(found).toHaveTextContent("Nobody can decide this");
  });

  it("adds a gap to an existing rule with room, and sends nothing until saved with a reason", async () => {
    const seen = setup(coverage([action({ held_uncovered: { total: 1, rows: [gap(GAP, "server-gap")] } })]), {
      [`POST /api/console/v1/approval-rules/${RULE}`]: { body: { rule_id: RULE } },
    });
    renderPage(<ApprovalRules />);
    const found = await card();
    await userEvent.click(within(found).getByText("Add to a rule"));
    const menu = within(found).getByText("Add to a rule").closest("details");
    if (menu === null) throw new Error("No menu");
    // Only the active rule in this Space that routes this action and has room.
    expect(within(menu).getAllByRole("button").map((button) => button.textContent)).toEqual(["Endpoint response", "New rule"]);
    await userEvent.click(within(menu).getByRole("button", { name: "Endpoint response" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit Endpoint response" });
    // The gap's target is not among the approvers page's targets, yet it is shown and checked.
    expect(within(dialog).getByRole("checkbox", { name: /server-gap/ })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /server-a/ })).toBeChecked();
    expect(seen.filter((call) => call.method === "POST")).toHaveLength(0);
    await userEvent.type(within(dialog).getByLabelText("Reason for this rule change"), "Cover the lapsed endpoint");
    const before = reads(seen);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save rule" }));
    await waitFor(() => { expect(seen.filter((call) => call.method === "POST")).toHaveLength(1); });
    expect(seen.find((call) => call.method === "POST")?.body).toEqual({
      name: "Endpoint response", group_id: GROUP, space_id: SPACE, actions: ["endpoint.isolate"], targets: [TARGET, GAP],
      reason: "Cover the lapsed endpoint",
    });
    // The save refreshes coverage once.
    await waitFor(() => { expect(reads(seen)).toBe(before + 1); });
  });

  it("starts a new rule with the Space, the action and the gap's target chosen", async () => {
    const seen = setup(coverage([action({ held_uncovered: { total: 1, rows: [gap(GAP, "server-gap")] } })]));
    renderPage(<ApprovalRules />);
    const found = await card();
    await userEvent.click(within(found).getByText("Add to a rule"));
    await userEvent.click(within(found).getByRole("button", { name: "New rule" }));
    const dialog = await screen.findByRole("dialog", { name: "Create approval rule" });
    expect(within(dialog).getByLabelText("Space")).toHaveValue(SPACE);
    expect(within(dialog).getByRole("checkbox", { name: "Isolate endpoint" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /server-gap/ })).toBeChecked();
    expect(within(dialog).getByRole("button", { name: "Save rule" })).toBeDisabled();
    expect(seen.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("assigns one person only in the write Space, prefilled, and only once confirmed", async () => {
    const seen = setup(
      coverage([action({ held_uncovered: { total: 1, rows: [gap(GAP, "server-gap")] } })], {
        spaces: [
          { space_id: SPACE, name: "Default", bundle_id: RULE, policy: "rules", actions: [action({ held_uncovered: { total: 1, rows: [gap(GAP, "server-gap")] } })] },
          { space_id: ELSEWHERE, name: "Elsewhere", bundle_id: RULE, policy: "rules", actions: [action({ held_uncovered: { total: 1, rows: [gap(TARGET, "server-a")] } })] },
        ],
      }),
      {
        "GET /api/console/v1/access": { body: { ...ACCESS, spaces: [...ACCESS.spaces, { space_id: ELSEWHERE, name: "Elsewhere" }] } },
        "POST /api/console/v1/approvers/assign": { body: { changed: true } },
      },
    );
    renderPage(<ApprovalRules />, {
      role: "ADMIN", mode: "ENFORCE", tenant: { name: "Acme", detail: "" }, space: { id: SPACE, name: "Default", archived: false },
      spaces: 2, allSpaces: true, person: { label: "A", detail: "", initials: "A" }, stop: null,
    } as Parameters<typeof renderPage>[1]);
    const found = await card();
    const elsewhere = within(found).getByRole("heading", { name: "Elsewhere" }).closest("section");
    if (elsewhere === null) throw new Error("No Elsewhere section");
    expect(elsewhere).toHaveTextContent("To assign one person, switch to Elsewhere first.");
    expect(within(elsewhere).queryByRole("button", { name: "Assign a person" })).toBeNull();
    const here = within(found).getByRole("heading", { name: "Default" }).closest("section");
    if (here === null) throw new Error("No Default section");
    await userEvent.click(within(here).getByRole("button", { name: "Assign a person" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    expect(within(dialog).getByLabelText("Canonical target")).toHaveValue(GAP);
    expect(within(dialog).getByLabelText("Action")).toHaveValue("endpoint.isolate");
    expect(seen.filter((call) => call.method === "POST")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "Assign" }));
    await waitFor(() => { expect(seen.filter((call) => call.method === "POST")).toHaveLength(1); });
    expect(seen.find((call) => call.method === "POST")?.body).toEqual({ approver: USER, target: GAP, action: "endpoint.isolate" });
  });

  it("is not read on a timer", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const seen = setup(coverage([action()]));
    renderPage(<ApprovalRules />);
    await card();
    expect(reads(seen)).toBe(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60_000); });
    expect(reads(seen)).toBe(1);
  });

  it("says when nothing is short, and that Observe holds nothing", async () => {
    setup(coverage([action()], { mode: "OBSERVE" }));
    renderPage(<ApprovalRules />);
    const found = await card();
    expect(found).toHaveTextContent("Every action the active policies can hold has enough people to decide it");
    expect(found).toHaveTextContent("Observe only: nothing is held while the workspace observes.");
  });

  it("lists thinly covered and requested-only resources apart from the held gaps", async () => {
    setup(coverage([action({
      thin: { total: 1, rows: [gap(TARGET, "server-a", 1)] },
      requested_uncovered: { total: 2, rows: [gap(GAP, "server-gap"), gap(FULL, null)] },
    })]));
    renderPage(<ApprovalRules />);
    const found = await card();
    expect(found).toHaveTextContent("Only 1 person can decide server-a, exactly the quorum; if one is away, its requests lapse.");
    expect(within(found).getByText(/2 other resources this action reached could not be decided if they were held/)).toBeInTheDocument();
    expect(found).toHaveTextContent("Unnamed resource");
  });
});
