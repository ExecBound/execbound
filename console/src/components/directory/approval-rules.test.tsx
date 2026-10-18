// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AccessPage, ApprovalRule, ApprovalRulesPage, ApproversPage } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, renderPage, type Answer } from "../../test/page";
import { AccessManagement } from "./AccessManagement";
import { ApprovalRules, eligibleReviewers } from "./ApprovalRules";

const GROUP = "11111111-1111-1111-1111-111111111111";
const SPACE = "22222222-2222-2222-2222-222222222222";
const USER = "33333333-3333-3333-3333-333333333333";
const TARGET = "44444444-4444-4444-4444-444444444444";
const OTHER = "55555555-5555-5555-5555-555555555555";
const RULE = "66666666-6666-6666-6666-666666666666";
const REVIEWER_GROUP: AccessPage["groups"][number] = { group_id: GROUP, name: "SOC reviewers", description: "Incident response", members: [USER], roles: [{ role: "approver", space_id: SPACE }] };
const ACCESS: AccessPage = {
  roles: [
    { id: "approver", name: "Approver", description: "Review assigned requests", permissions: ["approvals.decide"], scopes: ["WORKSPACE", "SPACE"] },
    { id: "viewer", name: "Viewer", description: "Read activity", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
  ],
  users: [{ principal_id: USER, label: "Dana Reyes", email: null, number: 2, kind: "HUMAN_APPROVER", active: true, managed: true, direct_roles: [], inherited_roles: [] }],
  groups: [REVIEWER_GROUP],
  spaces: [{ space_id: SPACE, name: "Production" }],
};
const SCOPES: ApproversPage = {
  assignments: [], approvers: [], actions: ["endpoint.isolate", "endpoint.lift_isolation"],
  targets: [{ canonical_target_id: TARGET, labels: "server-a" }, { canonical_target_id: OTHER, labels: "server-b" }],
};
const EXISTING: ApprovalRule = {
  rule_id: RULE, name: "Endpoint response", active: true, eligible_reviewers: 1,
  group_id: GROUP, group_name: "SOC reviewers", space_id: SPACE, space_name: "Production",
  actions: ["endpoint.isolate"], targets: [TARGET],
};
const RULES: ApprovalRulesPage = {
  rules: [EXISTING],
  actions: [{ id: "endpoint.isolate", name: "Isolate endpoint" }, { id: "endpoint.lift_isolation", name: "Lift isolation" }],
};

afterEach(() => { vi.unstubAllGlobals(); clearToasts(); });

function setup(routes: Record<string, Answer> = {}) {
  return answerWith({
    "GET /api/console/v1/access": { body: ACCESS },
    "GET /api/console/v1/approval-rules": { body: RULES },
    "GET /api/console/v1/approvers": { body: SCOPES },
    ...routes,
  });
}

describe("approval rule changes", () => {
  it("deletes only a confirmed unused group and refreshes the directory", async () => {
    let deleted = false;
    const seen = setup({
      "GET /api/console/v1/access": () => ({ body: { ...ACCESS, groups: deleted ? [] : [{ ...REVIEWER_GROUP, members: [], roles: [] }] } }),
      [`POST /api/console/v1/access/groups/${GROUP}/delete`]: () => { deleted = true; return { body: { changed: true } }; },
    });
    renderPage(<AccessManagement />);
    await userEvent.click(await screen.findByRole("button", { name: "Delete group" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete SOC reviewers?" });
    expect(within(dialog).getByRole("button", { name: "Delete group" })).toBeDisabled();
    expect(dialog).toHaveTextContent("Audit history remains");
    await userEvent.type(within(dialog).getByLabelText("Reason for deleting"), "Completed test");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete group" }));
    expect(await screen.findByText("Create a group for a team.")).toBeInTheDocument();
    expect(seen.filter((call) => call.method === "POST").map((call) => call.body)).toEqual([{ reason: "Completed test" }]);
  });
  it("counts active members once and respects Space scope and roles from other groups", () => {
    expect(eligibleReviewers(ACCESS, GROUP, SPACE)).toBe(1);
    expect(eligibleReviewers(ACCESS, GROUP, OTHER)).toBe(0);
    expect(eligibleReviewers({ ...ACCESS, users: ACCESS.users.map((u) => ({ ...u, active: false })) }, GROUP, SPACE)).toBe(0);
    const access = { ...ACCESS, groups: [
      { ...REVIEWER_GROUP, roles: [] },
      { ...REVIEWER_GROUP, group_id: OTHER, roles: [{ role: "approver" as const, space_id: null }] },
    ] };
    expect(eligibleReviewers(access, GROUP, SPACE)).toBe(1);
    expect(eligibleReviewers({ ...access, groups: [{ ...REVIEWER_GROUP, roles: [] }] }, GROUP, SPACE)).toBe(0);
  });
  it("previews eligible reviewers, warns about an empty group, and explains an empty resource search before saving", async () => {
    const access = { ...ACCESS, groups: [...ACCESS.groups, { group_id: OTHER, name: "Empty group", description: null, members: [], roles: [] }] };
    const seen = setup({ "GET /api/console/v1/access": { body: access } });
    renderPage(<ApprovalRules />);
    await userEvent.click(await screen.findByRole("button", { name: "Create approval rule" }));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() => { expect(within(dialog).getByLabelText("Rule name")).toHaveFocus(); });
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), GROUP);
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    expect(within(dialog).getByText("1 eligible reviewer in Production")).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), OTHER);
    expect(within(dialog).getByRole("status")).toHaveTextContent("No eligible reviewers");
    await userEvent.type(within(dialog).getByLabelText("Find a resource"), "no-such-resource");
    expect(within(dialog).getByText("No matching resources. Try a different name or ID.")).toBeInTheDocument();
    expect(seen.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("requires explicit action and resource selection, preserves a refused form, and retries the exact scoped change", async () => {
    let attempts = 0;
    const seen = setup({
      "POST /api/console/v1/approval-rules": () => ++attempts === 1
        ? { status: 409, body: { code: "CONFLICT" } } : { body: { rule_id: RULE } },
    });
    renderPage(<ApprovalRules />);
    await userEvent.click(await screen.findByRole("button", { name: "Create approval rule" }));
    const dialog = await screen.findByRole("dialog", { name: "Create approval rule" });
    const save = within(dialog).getByRole("button", { name: "Save rule" });
    expect(save).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Rule name"), "New response");
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), GROUP);
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    await userEvent.type(within(dialog).getByLabelText("Reason for this rule change"), "Review selected production endpoints");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Isolate endpoint" }));
    expect(save).toBeDisabled();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /server-a/ }));
    await userEvent.type(within(dialog).getByLabelText("Find a resource"), "server-b");
    expect(within(dialog).queryByRole("checkbox", { name: /server-a/ })).toBeNull();
    expect(save).toBeEnabled();
    await userEvent.click(save);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Something changed first");
    expect(within(dialog).getByLabelText("Rule name")).toHaveValue("New response");
    expect(within(dialog).getByRole("checkbox", { name: "Isolate endpoint" })).toBeChecked();
    await userEvent.click(save);
    await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
    const posts = seen.filter((call) => call.method === "POST");
    expect(posts).toHaveLength(2);
    for (const post of posts) {
      expect(post.body).toEqual({ name: "New response", group_id: GROUP, space_id: SPACE, actions: ["endpoint.isolate"], targets: [TARGET], reason: "Review selected production endpoints" });
      expect(post.headers.get("x-csrf-token")).toBe("token-under-test");
    }
    expect(seen.filter((call) => call.method === "GET" && call.path.endsWith("/approval-rules"))).toHaveLength(2);
  });

  it("discards cancelled edits when reopening, including the old reason and hidden resource filter", async () => {
    const seen = setup();
    renderPage(<ApprovalRules />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit rule" }));
    let dialog = await screen.findByRole("dialog", { name: "Edit Endpoint response" });
    await userEvent.clear(within(dialog).getByLabelText("Rule name"));
    await userEvent.type(within(dialog).getByLabelText("Rule name"), "Discard me");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Isolate endpoint" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Lift isolation" }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /server-a/ }));
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /server-b/ }));
    await userEvent.type(within(dialog).getByLabelText("Find a resource"), "server-b");
    await userEvent.type(within(dialog).getByLabelText("Reason for this rule change"), "Discard reason");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Edit rule" }));
    dialog = await screen.findByRole("dialog", { name: "Edit Endpoint response" });
    expect(within(dialog).getByLabelText("Rule name")).toHaveValue("Endpoint response");
    expect(within(dialog).getByRole("checkbox", { name: "Isolate endpoint" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "Lift isolation" })).not.toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /server-a/ })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /server-b/ })).not.toBeChecked();
    expect(within(dialog).getByLabelText("Find a resource")).toHaveValue("");
    expect(within(dialog).getByLabelText("Reason for this rule change")).toHaveValue("");
    expect(seen.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("disables only the selected rule with a reason, then explicitly enables the existing rule through edit", async () => {
    let active = true;
    const seen = setup({
      "GET /api/console/v1/approval-rules": () => ({ body: { ...RULES, rules: [{ ...EXISTING, active }] } }),
      [`POST /api/console/v1/approval-rules/${RULE}/disable`]: () => { active = false; return { body: { rule_id: RULE } }; },
      [`POST /api/console/v1/approval-rules/${RULE}`]: () => { active = true; return { body: { rule_id: RULE } }; },
    });
    renderPage(<ApprovalRules />);
    await userEvent.click(await screen.findByRole("button", { name: "Disable rule" }));
    let dialog = await screen.findByRole("dialog", { name: "Disable Endpoint response?" });
    expect(within(dialog).getByText(/already approved work awaiting execution/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Disable rule" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Reason for disabling"), "Discard this reason");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Disable rule" }));
    dialog = await screen.findByRole("dialog", { name: "Disable Endpoint response?" });
    expect(within(dialog).getByLabelText("Reason for disabling")).toHaveValue("");
    await userEvent.type(within(dialog).getByLabelText("Reason for disabling"), "Pause review routing");
    await userEvent.click(within(dialog).getByRole("button", { name: "Disable rule" }));
    await screen.findByText("Disabled", { exact: true });
    expect(screen.queryByRole("button", { name: "Disable rule" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Edit rule" }));
    dialog = await screen.findByRole("dialog", { name: "Edit Endpoint response" });
    await userEvent.type(within(dialog).getByLabelText("Reason for this rule change"), "Resume review routing");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save and enable rule" }));
    await screen.findByText("Active", { exact: true });
    const posts = seen.filter((call) => call.method === "POST");
    expect(posts.map((call) => call.path)).toEqual([`/api/console/v1/approval-rules/${RULE}/disable`, `/api/console/v1/approval-rules/${RULE}`]);
    expect(posts[0]?.body).toEqual({ reason: "Pause review routing" });
    expect(posts[1]?.body).toEqual({ name: EXISTING.name, group_id: GROUP, space_id: SPACE, actions: EXISTING.actions, targets: EXISTING.targets, reason: "Resume review routing" });
    expect(posts.every((call) => call.headers.get("x-csrf-token") === "token-under-test")).toBe(true);
  });

  it("offers no rule form when required access cannot be read", async () => {
    setup({ "GET /api/console/v1/access": { status: 403, body: { code: "FORBIDDEN" } } });
    renderPage(<ApprovalRules />);
    expect(await screen.findByText("Approval rules could not be loaded.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create approval rule" })).toBeNull();
  });
});

describe("group editor state and refusal handling", () => {
  it("reopens group details from saved values instead of cancelled edits", async () => {
    setup();
    renderPage(<AccessManagement />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit group" }));
    let dialog = await screen.findByRole("dialog", { name: "Edit SOC reviewers" });
    await userEvent.clear(within(dialog).getByLabelText("Group name"));
    await userEvent.type(within(dialog).getByLabelText("Group name"), "Discarded team");
    await userEvent.clear(within(dialog).getByLabelText("Description"));
    await userEvent.type(within(dialog).getByLabelText("Description"), "Discarded description");
    await userEvent.type(within(dialog).getByLabelText("Reason for this change"), "Discarded reason");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Edit group" }));
    dialog = await screen.findByRole("dialog", { name: "Edit SOC reviewers" });
    expect(within(dialog).getByLabelText("Group name")).toHaveValue("SOC reviewers");
    expect(within(dialog).getByLabelText("Description")).toHaveValue("Incident response");
    expect(within(dialog).getByLabelText("Reason for this change")).toHaveValue("");
  });

  it("restores saved membership after cancel and preserves a refused removal for explicit retry", async () => {
    let attempts = 0;
    const seen = setup({ [`POST /api/console/v1/access/groups/${GROUP}/members`]: () => ++attempts === 1
      ? { status: 409, body: { code: "CONFLICT" } } : { body: { changed: true } } });
    renderPage(<AccessManagement />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit members" }));
    let dialog = await screen.findByRole("dialog", { name: "Members of SOC reviewers" });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Dana Reyes" }));
    await userEvent.type(within(dialog).getByLabelText("Reason for this change"), "Discarded reason");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Edit members" }));
    dialog = await screen.findByRole("dialog", { name: "Members of SOC reviewers" });
    expect(within(dialog).getByRole("checkbox", { name: "Dana Reyes" })).toBeChecked();
    expect(within(dialog).getByLabelText("Reason for this change")).toHaveValue("");
    await userEvent.click(within(dialog).getByRole("checkbox", { name: "Dana Reyes" }));
    await userEvent.type(within(dialog).getByLabelText("Reason for this change"), "Remove retired reviewer");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save members" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Something changed first");
    expect(within(dialog).getByRole("checkbox", { name: "Dana Reyes" })).not.toBeChecked();
    expect(within(dialog).getByLabelText("Reason for this change")).toHaveValue("Remove retired reviewer");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save members" }));
    await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
    expect(seen.filter((call) => call.method === "POST").map((call) => call.body)).toEqual([
      { members: [], reason: "Remove retired reviewer" }, { members: [], reason: "Remove retired reviewer" },
    ]);
  });

  it("restores group roles after cancel and retains role and scope when the server refuses a save", async () => {
    const seen = setup({ [`POST /api/console/v1/access/groups/${GROUP}/roles`]: { status: 403, body: { code: "FORBIDDEN" } } });
    renderPage(<AccessManagement />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit group roles" }));
    let dialog = await screen.findByRole("dialog", { name: "Roles for SOC reviewers" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Role 1"), "viewer");
    await userEvent.type(within(dialog).getByLabelText("Reason for this change"), "Discarded reason");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Edit group roles" }));
    dialog = await screen.findByRole("dialog", { name: "Roles for SOC reviewers" });
    expect(within(dialog).getByLabelText("Role 1")).toHaveValue("approver");
    expect(within(dialog).getByLabelText("Scope 1")).toHaveValue(SPACE);
    expect(within(dialog).getByLabelText("Reason for this change")).toHaveValue("");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role 1"), "viewer");
    await userEvent.type(within(dialog).getByLabelText("Reason for this change"), "Read-only responders");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save group roles" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("This is not yours to do");
    expect(within(dialog).getByLabelText("Role 1")).toHaveValue("viewer");
    expect(within(dialog).getByLabelText("Scope 1")).toHaveValue(SPACE);
    expect(within(dialog).getByLabelText("Reason for this change")).toHaveValue("Read-only responders");
    expect(seen.find((call) => call.method === "POST")?.body).toEqual({ grants: [{ role: "viewer", space_id: SPACE }], reason: "Read-only responders" });
  });
});
