// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AccessPage, ApprovalRulesPage, TeammateInvitationRow } from "../../api/types.gen";
import { answerWith, renderPage } from "../../test/page";
import { clearToasts } from "../../lib/toast";
import { InviteTeammate } from "./InviteTeammate";
import { TeammateInvitations } from "./TeammateInvitations";

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

const SPACE = "99999999-9999-9999-9999-999999999999";
const LAB = "88888888-8888-8888-8888-888888888888";
const PENDING = "77777777-7777-7777-7777-777777777777";
const SENT = "11111111-1111-1111-1111-111111111111";
const FAILED = "22222222-2222-2222-2222-222222222222";
const SENDING = "33333333-3333-3333-3333-333333333333";
const EXPIRED = "44444444-4444-4444-4444-444444444444";
const REVOKED = "55555555-5555-5555-5555-555555555555";
const ACCEPTED = "66666666-6666-6666-6666-666666666666";
const NIGHT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ADMINS = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const EVERYWHERE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const QUIET = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const USER = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const RULE = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const TARGET = "12121212-1212-4212-8212-121212121212";

const ACCESS: AccessPage = {
  roles: [
    { id: "administrator", name: "Administrator", description: "Workspace administration", permissions: [], scopes: ["WORKSPACE"] },
    { id: "policy_manager", name: "Policy manager", description: "Manage policies", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
    { id: "approver", name: "Approver", description: "Review assigned requests", permissions: ["approvals.decide"], scopes: ["WORKSPACE", "SPACE"] },
    { id: "viewer", name: "Viewer", description: "Read activity", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
  ],
  spaces: [
    { space_id: SPACE, name: "Production" },
    { space_id: LAB, name: "Lab" },
  ],
  groups: [],
  users: [],
};

const GROUPED: AccessPage = {
  ...ACCESS,
  users: [
    { principal_id: USER, label: "Dana Reyes", email: null, number: 2, kind: "HUMAN_APPROVER", active: true, managed: true, direct_roles: [{ role: "approver", space_id: SPACE }], inherited_roles: [] },
  ],
  groups: [
    { group_id: NIGHT, name: "Night shift", description: null, members: [USER], roles: [] },
    { group_id: ADMINS, name: "Admins", description: null, members: [], roles: [{ role: "administrator", space_id: null }] },
    { group_id: EVERYWHERE, name: "All reviewers", description: null, members: [], roles: [{ role: "approver", space_id: null }] },
    { group_id: QUIET, name: "<b>Quiet</b>", description: null, members: [], roles: [{ role: "approver", space_id: SPACE }] },
  ],
};

const RULES: ApprovalRulesPage = {
  rules: [
    {
      rule_id: RULE, name: "Production endpoint response", active: true, eligible_reviewers: 1,
      group_id: NIGHT, group_name: "Night shift", space_id: SPACE, space_name: "Production",
      actions: ["endpoint.isolate"], targets: [TARGET],
    },
  ],
  actions: [{ id: "endpoint.isolate", name: "Isolate endpoint" }],
};

function row(overrides: Partial<TeammateInvitationRow>): TeammateInvitationRow {
  return {
    invitation_id: PENDING,
    email: "new@example.org",
    grants: [{ role: "viewer", space_id: null }],
    state: "PENDING",
    created_at: "2026-09-20T08:00:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    sends: 1,
    last_error: null,
    delivered_at: null,
    reviewer_group_id: null,
    reviewer_group_name: null,
    ...overrides,
  };
}

async function openDialog() {
  await userEvent.click(await screen.findByRole("button", { name: "Invite teammate" }));
  const dialog = await screen.findByRole("dialog", { name: "Invite a teammate" });
  await within(dialog).findByRole("option", { name: "Administrator" });
  return dialog;
}

function posted(calls: ReturnType<typeof answerWith>) {
  return calls.filter((call) => call.path === "/api/console/v1/teammate-invitations" && call.method === "POST");
}

describe("inviting a teammate", () => {
  it("defaults the dialog to Viewer and disables the Space select for Administrator", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    expect(within(dialog).getByLabelText("Role")).toHaveValue("viewer");
    expect(within(dialog).getByLabelText("Space")).toBeEnabled();
    expect(within(dialog).queryByLabelText("Reviewer group")).toBeNull();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "administrator");
    expect(within(dialog).getByLabelText("Space")).toBeDisabled();
  });

  it("submits the create mutation with the chosen grant", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      "GET /api/console/v1/approval-rules": { body: RULES },
      "POST /api/console/v1/teammate-invitations": {
        body: { invitation_id: PENDING, expires_at: "2030-01-01T00:00:00Z" },
      },
    });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    await userEvent.type(within(dialog).getByLabelText("Email"), "new@example.org");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    await userEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
    await waitFor(() => {
      expect(posted(calls)).toHaveLength(1);
    });
    expect(posted(calls)[0]?.body).toEqual({
      email: "new@example.org",
      grants: [{ role: "approver", space_id: SPACE }],
    });
  });

  it("offers an Approver's reviewer group with its grants, disabling the ones the server refuses", async () => {
    answerWith({
      "GET /api/console/v1/access": { body: GROUPED },
      "GET /api/console/v1/approval-rules": { body: RULES },
    });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    const select = within(dialog).getByLabelText("Reviewer group");
    expect(within(select).getByRole("option", { name: "None: add them to a group later" })).toBeEnabled();
    expect(within(select).getByRole("option", { name: "Night shift · No roles" })).toBeEnabled();
    expect(
      within(select).getByRole("option", { name: "Admins · Administrator everywhere (grants more than review)" }),
    ).toBeDisabled();
    const everywhere = within(select).getByRole("option", {
      name: "All reviewers · Approver everywhere (grants more than this invitation)",
    });
    expect(everywhere).toBeDisabled();
    // Markup in a group's name is the group's name, never markup.
    expect(within(select).getByRole("option", { name: "<b>Quiet</b> · Approver in Production" })).toBeEnabled();

    // An invitation for every Space covers a workspace-wide Approver grant.
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), "");
    expect(within(select).getByRole("option", { name: "All reviewers · Approver everywhere" })).toBeEnabled();
  });

  it("shows the rules that name the chosen group and who could decide them now", async () => {
    answerWith({
      "GET /api/console/v1/access": { body: GROUPED },
      "GET /api/console/v1/approval-rules": { body: RULES },
    });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), NIGHT);
    expect(
      await within(dialog).findByText("Production endpoint response: Isolate endpoint on 1 resource in Production."),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        "1 eligible reviewer in Production now; they join once they accept, if their Approver role covers that Space.",
      ),
    ).toBeInTheDocument();

    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), QUIET);
    expect(
      await within(dialog).findByText(/No approval rule names this group yet, so they will not be able to decide anything until one does\./),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Approval rules" })).toHaveAttribute("href", "/approvers");
  });

  it("points at Team & access when there are no groups", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    expect(within(dialog).queryByLabelText("Reviewer group")).toBeNull();
    expect(within(dialog).getByText(/No reviewer groups yet\./)).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Team & access" })).toHaveAttribute("href", "/access");
  });

  it("posts the chosen group, and none for a Viewer", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: GROUPED },
      "GET /api/console/v1/approval-rules": { body: RULES },
      "POST /api/console/v1/teammate-invitations": {
        body: { invitation_id: PENDING, expires_at: "2030-01-01T00:00:00Z" },
      },
    });
    renderPage(<InviteTeammate />);
    let dialog = await openDialog();
    await userEvent.type(within(dialog).getByLabelText("Email"), "riley@example.org");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Space"), SPACE);
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), NIGHT);
    await userEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
    await waitFor(() => {
      expect(posted(calls)).toHaveLength(1);
    });
    expect(posted(calls)[0]?.body).toEqual({
      email: "riley@example.org",
      grants: [{ role: "approver", space_id: SPACE }],
      reviewer_group_id: NIGHT,
    });

    dialog = await openDialog();
    await userEvent.type(within(dialog).getByLabelText("Email"), "sam@example.org");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), NIGHT);
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "viewer");
    expect(within(dialog).queryByLabelText("Reviewer group")).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
    await waitFor(() => {
      expect(posted(calls)).toHaveLength(2);
    });
    expect(posted(calls)[1]?.body).toEqual({
      email: "sam@example.org",
      grants: [{ role: "viewer", space_id: null }],
    });
  });

  it("marks the group invalid when the server refuses it", async () => {
    answerWith({
      "GET /api/console/v1/access": { body: GROUPED },
      "GET /api/console/v1/approval-rules": { body: RULES },
      "POST /api/console/v1/teammate-invitations": {
        status: 400,
        body: { code: "INVALID_BODY", detail: "Invalid request", fields: ["reviewer_group_id"] },
      },
    });
    renderPage(<InviteTeammate />);
    const dialog = await openDialog();
    await userEvent.type(within(dialog).getByLabelText("Email"), "riley@example.org");
    await userEvent.selectOptions(within(dialog).getByLabelText("Role"), "approver");
    await userEvent.selectOptions(within(dialog).getByLabelText("Reviewer group"), NIGHT);
    await userEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
    expect(
      await within(dialog).findByText(
        "That reviewer group grants more than this invitation, or is no longer in this workspace. Choose another group, or none.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Reviewer group")).toHaveAttribute("aria-invalid", "true");
  });
});

describe("the invitations list", () => {
  it("lists open and expired invitations, leaving accepted and revoked ones out", async () => {
    answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      "GET /api/console/v1/teammate-invitations": {
        body: {
          invitations: [
            row({ invitation_id: SENT, email: "sent@example.org", delivered_at: "2026-09-20T08:05:00Z" }),
            row({ invitation_id: FAILED, email: "failed@example.org", last_error: "RECEIVER_UNAVAILABLE" }),
            row({ invitation_id: SENDING, email: "sending@example.org" }),
            row({ invitation_id: EXPIRED, email: "expired@example.org", expires_at: "2020-01-01T00:00:00Z" }),
            row({ invitation_id: REVOKED, email: "revoked@example.org", state: "REVOKED" }),
            row({ invitation_id: ACCEPTED, email: "accepted@example.org", state: "ACCEPTED" }),
          ],
        },
      },
    });
    renderPage(<TeammateInvitations />);
    expect(await screen.findByRole("heading", { name: "Invitations" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: /Teammate invitations/ });
    for (const word of ["Sent", "Failed", "Sending", "Expired"]) {
      expect(within(table).getByText(word)).toBeInTheDocument();
    }
    // An accepted invitation is a person on the People list now, and a revoked one was ended
    // on purpose: neither is listed here.
    for (const gone of ["accepted@example.org", "revoked@example.org"]) {
      expect(table).not.toHaveTextContent(gone);
    }
    expect(within(table).getAllByRole("row").slice(1)).toHaveLength(4);
    expect(within(table).queryAllByRole("button", { name: "Resend" })).toHaveLength(3);
    expect(within(table).queryAllByRole("button", { name: "Revoke" })).toHaveLength(3);
    const lapsed = within(table).getByText("expired@example.org").closest("tr");
    expect(lapsed).not.toBeNull();
    expect(within(lapsed as HTMLElement).getAllByRole("button").map((button) => button.textContent)).toEqual(["Invite again"]);
  });

  it("says nothing is open once every invitation was accepted", async () => {
    answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      "GET /api/console/v1/teammate-invitations": {
        body: { invitations: [row({ invitation_id: ACCEPTED, email: "accepted@example.org", state: "ACCEPTED" })] },
      },
    });
    renderPage(<TeammateInvitations />);
    expect(await screen.findByText("No open invitations.")).toBeInTheDocument();
    expect(screen.queryByText("accepted@example.org")).toBeNull();
  });

  it("invites again with the same address, grants and group, and refreshes on the answer", async () => {
    let listed = 0;
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const grants = [{ role: "approver" as const, space_id: SPACE }];
    const calls = answerWith({
      "GET /api/console/v1/access": { body: GROUPED },
      "GET /api/console/v1/teammate-invitations": () => {
        listed += 1;
        return {
          body: {
            invitations: [
              row({
                invitation_id: EXPIRED,
                email: "lapsed@example.org",
                grants,
                expires_at: "2020-01-01T00:00:00Z",
                reviewer_group_id: QUIET,
                reviewer_group_name: "<b>Quiet</b>",
              }),
            ],
          },
        };
      },
      "POST /api/console/v1/teammate-invitations": async () => {
        await held;
        return { body: { invitation_id: PENDING, expires_at: "2030-01-01T00:00:00Z" } };
      },
    });
    renderPage(<TeammateInvitations />);
    const table = await screen.findByRole("table", { name: /Teammate invitations/ });
    expect(within(table).getByText("Reviewer group: <b>Quiet</b>")).toBeInTheDocument();
    const button = within(table).getByRole("button", { name: "Invite again" });
    await userEvent.click(button);
    await waitFor(() => {
      expect(button).toBeDisabled();
    });
    const before = listed;
    release();
    await waitFor(() => {
      expect(listed).toBeGreaterThan(before);
    });
    expect(posted(calls).map((call) => call.body)).toEqual([
      { email: "lapsed@example.org", grants, reviewer_group_id: QUIET },
    ]);
  });

  it("resends a pending invitation and revokes only after confirming", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      "GET /api/console/v1/teammate-invitations": { body: { invitations: [row({})] } },
      [`POST /api/console/v1/teammate-invitations/${PENDING}/resend`]: { body: { changed: true } },
      [`POST /api/console/v1/teammate-invitations/${PENDING}/revoke`]: { body: { changed: true } },
    });
    renderPage(<TeammateInvitations />);
    const table = await screen.findByRole("table", { name: /Teammate invitations/ });
    await userEvent.click(within(table).getByRole("button", { name: "Resend" }));
    await waitFor(() => {
      expect(calls.some((call) => call.path.endsWith("/resend"))).toBe(true);
    });

    await userEvent.click(within(table).getByRole("button", { name: "Revoke" }));
    // The row action only opens the confirmation; nothing is sent yet.
    expect(calls.some((call) => call.path.endsWith("/revoke"))).toBe(false);
    const dialog = await screen.findByRole("dialog", { name: /Revoke the invitation to new@example.org/ });
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() => {
      expect(calls.some((call) => call.path.endsWith("/revoke"))).toBe(true);
    });
  });
});
