// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

import type { ApproversPage, CredentialsPage } from "../../api/types.gen";
import { ApproversList, AssignScope } from "./ApproversList";
import { called, serve } from "../../test/api";
import { CredentialsList, IssueCredential } from "./CredentialsList";

const AGENT = "22222222-2222-2222-2222-222222222222";
const HUMAN = "33333333-3333-3333-3333-333333333333";
const ADMIN = "44444444-4444-4444-4444-444444444444";
const TARGET = "55555555-5555-5555-5555-555555555555";

const CREDENTIALS: CredentialsPage = {
  principals: [
    { principal_id: AGENT, kind: "AGENT", active: true, label: "Triage bot", number: 1, live: 1 },
    { principal_id: HUMAN, kind: "HUMAN_APPROVER", active: true, label: null, number: 3, live: 0 },
    { principal_id: ADMIN, kind: "ADMIN", active: true, label: "A. Rivera", number: 1, live: 1 },
    { principal_id: TARGET, kind: "AGENT", active: false, label: "Retired", number: 2, live: 0 },
  ],
  credentials: [
    { credential_id: "66666666-6666-6666-6666-666666666666", principal_id: AGENT, kind: "AGENT", label: "Triage bot", email: null, number: 12, principal_number: 1, issued_at: "2026-09-19T08:00:00Z", expires_at: "2026-09-19T16:00:00Z", revoked_at: null, state: "live", failures_24h: 0 },
    { credential_id: "77777777-7777-7777-7777-777777777777", principal_id: ADMIN, kind: "ADMIN", label: "A. Rivera", email: "rivera@example.com", number: null, principal_number: 1, issued_at: "2026-09-19T08:00:00Z", expires_at: "2026-09-20T08:00:00Z", revoked_at: null, state: "live", failures_24h: 3 },
    { credential_id: "88888888-8888-8888-8888-888888888888", principal_id: HUMAN, kind: "HUMAN_APPROVER", label: null, email: null, number: null, principal_number: 3, issued_at: "2026-09-01T08:00:00Z", expires_at: "2026-09-02T08:00:00Z", revoked_at: null, state: "expired", failures_24h: 0 },
  ],
  live: 2,
};

const APPROVERS: ApproversPage = {
  assignments: [
    { approver_id: HUMAN, label: "Dana <b>Reyes</b>", email: "dana@example.com", number: 3, canonical_target_id: TARGET, labels: "device-01", action: "endpoint.isolate" },
  ],
  approvers: [{ principal_id: HUMAN, label: "Dana <b>Reyes</b>", email: "dana@example.com", number: 3 }],
  targets: [{ canonical_target_id: TARGET, labels: "device-01" }],
  actions: ["endpoint.isolate", "endpoint.lift_isolation"],
};

function mount(element: ReactNode, initial: string) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/credentials", element),
      page("/approvers", element),
      page("/agents/$agentId", <p>Agent</p>),
      page("/people/$personId", <p>Person</p>),
    ]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the credentials list", () => {
  it("leads with agent credentials and keeps legacy human access in advanced details", async () => {
    mount(<CredentialsList data={CREDENTIALS} />, "/credentials");
    const table = await screen.findByRole("table", { name: /API keys in this tenant/ });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(within(rows[0] ?? table).getByRole("link", { name: "Triage bot" })).toHaveAttribute("href", `/agents/${AGENT}`);
    // A key and its agent read by number and name; no identifier prefix is on the row.
    expect(rows[0]).toHaveTextContent("Key 12");
    expect(rows[0]).not.toHaveTextContent("66666666");
    expect(rows[0]).not.toHaveTextContent("22222222");
    expect(within(rows[0] ?? table).getByRole("button", { name: "Revoke key 12" })).toBeInTheDocument();
    expect(screen.getByText("Advanced: legacy human and administrator credentials").closest("details")).not.toHaveAttribute("open");
    expect(screen.getByText("Live API keys").nextSibling).toHaveTextContent("1");
    await userEvent.click(screen.getByText("Advanced: legacy human and administrator credentials"));
    const legacy = screen.getByRole("table", { name: /Legacy human/ });
    const legacyRows = within(legacy).getAllByRole("row").slice(1);
    expect(legacyRows).toHaveLength(2);
    expect(within(legacyRows[0] ?? legacy).getByRole("link", { name: "A. Rivera" })).toHaveAttribute("href", `/people/${ADMIN}`);
    expect(within(legacyRows[0] ?? legacy).getByText("owner tooling")).toBeInTheDocument();
    expect(within(legacyRows[0] ?? legacy).queryByRole("button")).toBeNull();
    // A person's credential names its holder the way People does: here by number, beside
    // the name where the id prefix was.
    expect(legacyRows[0]).toHaveTextContent("A. Rivera User 1");
    expect(within(legacyRows[1] ?? legacy).getByRole("link", { name: "User 3" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(legacy).not.toHaveTextContent(HUMAN.slice(0, 8));
    expect(within(legacyRows[1] ?? legacy).queryByRole("button")).toBeNull();
    expect(within(legacyRows[1] ?? legacy).getByText("expired")).toHaveClass("badge-stale");
    await userEvent.click(within(rows[0] ?? table).getByRole("button", { name: "Revoke key 12" }));
    expect(await screen.findByRole("dialog", { name: "Revoke API key 12?" })).toBeInTheDocument();
  });

  it("names an unlabelled agent by its number and deletes a spent key after asking", async () => {
    const [agent] = CREDENTIALS.credentials;
    if (agent === undefined) throw new Error("fixture");
    const spent = { ...agent, label: null, state: "revoked" as const, revoked_at: "2026-09-19T09:00:00Z" };
    const calls = serve({
      "/api/console/v1/credentials/66666666-6666-6666-6666-666666666666/delete": { ...CREDENTIALS, credentials: [] },
    });
    mount(<CredentialsList data={{ ...CREDENTIALS, credentials: [spent] }} />, "/credentials");
    const table = await screen.findByRole("table", { name: /API keys in this tenant/ });
    expect(within(table).getByRole("link", { name: "Agent 1" })).toHaveAttribute("href", `/agents/${AGENT}`);
    expect(within(table).queryByRole("button", { name: /^Revoke/ })).toBeNull();
    await userEvent.click(within(table).getByRole("button", { name: "Delete key 12" }));
    const asked = await screen.findByRole("dialog", { name: "Delete API key 12?" });
    expect(asked).toHaveTextContent("The audit history keeps when it was issued and revoked.");
    await userEvent.click(within(asked).getByRole("button", { name: "Delete" }));
    await waitFor(() => {
      expect(called(calls, "POST", "/api/console/v1/credentials/66666666-6666-6666-6666-666666666666/delete")).toBe(true);
    });
  });

  it("shows a key issued to never expire as Never, whatever offset the time arrives in", async () => {
    const [agent] = CREDENTIALS.credentials;
    if (agent === undefined) throw new Error("fixture");
    mount(<CredentialsList data={{ ...CREDENTIALS, credentials: [{ ...agent, expires_at: "9999-12-30T19:00:00-05:00" }] }} />, "/credentials");
    const table = await screen.findByRole("table", { name: /API keys in this tenant/ });
    expect(within(table).getByText("Never")).toBeInTheDocument();
  });

  it("offers active agents by name and a new one, keeping human sign-in out of issuance", async () => {
    mount(<IssueCredential data={CREDENTIALS} />, "/credentials");
    await userEvent.click(await screen.findByRole("button", { name: "Issue an API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Issue an API key" });
    const options = within(within(dialog).getByLabelText("Agent"))
      .getAllByRole("option")
      .map((option) => option.textContent);
    expect(options).toEqual(["Triage bot · 1 live key", "New agent…"]);
    expect(within(dialog).getByLabelText("Agent")).toHaveValue(AGENT);
    expect(options.join(" ")).not.toContain("A. Rivera");
    expect(options.join(" ")).not.toContain("Retired");
    // No lifetime is chosen for the person (AK1): the form waits for one.
    expect(within(dialog).getByLabelText("Lifetime")).toHaveValue("");
    expect(within(dialog).getByRole("option", { name: "Choose a lifetime" })).toBeDisabled();
    expect(within(dialog).getByText(/usually needs 30 or 90 days/)).toBeInTheDocument();
    expect(within(within(dialog).getByLabelText("Lifetime")).getByRole("option", { name: "Never" })).toHaveValue("never");
    expect(within(dialog).getByRole("button", { name: "Issue API key" })).toBeDisabled();
    await userEvent.selectOptions(within(dialog).getByLabelText("Lifetime"), "720");
    expect(within(dialog).getByRole("button", { name: "Issue API key" })).toBeEnabled();
  });

  it("forgets a refused issue when the dialog opens again", async () => {
    serve({
      "/api/console/v1/credentials/issue": () =>
        new Response(JSON.stringify({ code: "INVALID_PRINCIPAL", detail: "x" }), {
          status: 400,
          headers: { "content-type": "application/json" },
        }),
    });
    mount(<IssueCredential data={CREDENTIALS} />, "/credentials");
    await userEvent.click(await screen.findByRole("button", { name: "Issue an API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Issue an API key" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Lifetime"), "8");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue API key" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("That principal cannot be changed from here.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await userEvent.click(screen.getByRole("button", { name: "Issue an API key" }));
    const again = await screen.findByRole("dialog", { name: "Issue an API key" });
    expect(within(again).queryByRole("alert")).toBeNull();
  });

  it("creates a named agent for the key, and needs the name first", async () => {
    const calls = serve({
      "/api/console/v1/credentials/issue": {
        token: "eb1.secret",
        credential_id: "99999999-9999-9999-9999-999999999999",
        principal_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        kind: "AGENT",
        expires_at: "2026-09-20T08:00:00Z",
        number: 13,
      },
    });
    mount(<IssueCredential data={{ ...CREDENTIALS, principals: [] }} />, "/credentials");
    await userEvent.click(await screen.findByRole("button", { name: "Issue an API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Issue an API key" });
    expect(within(dialog).getByLabelText("Agent")).toHaveValue("new:AGENT");
    expect(within(dialog).getByRole("button", { name: "Issue API key" })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Name"), "Coding agent on my laptop");
    expect(within(dialog).getByRole("button", { name: "Issue API key" })).toBeDisabled();
    await userEvent.selectOptions(within(dialog).getByLabelText("Lifetime"), "8");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue API key" }));
    expect(await screen.findByRole("dialog", { name: "Copy the API key now" })).toHaveTextContent("API key 13 is shown once.");
    const request = calls.find((call) => call.path.endsWith("/credentials/issue"));
    expect(request?.body).toEqual({ principal: "new:AGENT", lifetime: "8", label: "Coding agent on my laptop" });
  });
});

describe("the approver scopes", () => {
  it("lists assignments with labels as text and asks before unassigning", async () => {
    mount(<ApproversList data={APPROVERS} />, "/approvers");
    const table = await screen.findByRole("table", { name: /Active assignments/ });
    expect(within(table).getByRole("link", { name: "Dana <b>Reyes</b>" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(document.querySelector("b")).toBeNull();
    expect(table).toHaveTextContent("55555555 · device-01");
    // The approver's number sits beside the name, where the id prefix was.
    expect(within(table).getAllByRole("cell")[0]).toHaveTextContent("Dana <b>Reyes</b> User 3");
    expect(within(table).getAllByRole("cell")[0]).not.toHaveTextContent(HUMAN.slice(0, 8));
    expect(screen.getByText("Active assignments").nextSibling).toHaveTextContent("1");
    expect(screen.getByText("1 approver · 1 target")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Unassign User 3 from endpoint.isolate on 55555555" }));
    const dialog = await screen.findByRole("dialog", { name: "Unassign User 3 from endpoint.isolate on 55555555?" });
    expect(within(dialog).getByRole("button", { name: "Unassign" })).toHaveClass("btn-danger");
  });

  it("names an approver without a label by their email, else by their number", async () => {
    const [assigned] = APPROVERS.assignments;
    if (assigned === undefined) throw new Error("fixture");
    const data: ApproversPage = {
      ...APPROVERS,
      assignments: [{ ...assigned, label: null }, { ...assigned, label: null, email: null, action: "endpoint.lift_isolation" }],
      approvers: [{ principal_id: HUMAN, label: null, email: "dana@example.com", number: 3 }],
    };
    mount(<><ApproversList data={data} /><AssignScope data={data} /></>, "/approvers");
    const table = await screen.findByRole("table", { name: /Active assignments/ });
    expect(within(table).getByRole("link", { name: "dana@example.com" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(within(table).getByRole("link", { name: "User 3" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(table).not.toHaveTextContent(/unlabelled/i);
    await userEvent.click(screen.getByRole("button", { name: "Assign an approver" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    expect(within(within(dialog).getByLabelText("Approver")).getByRole("option")).toHaveTextContent("dana@example.com · User 3");
  });

  it("assigns from this tenant's approvers, targets and the catalog's actions", async () => {
    mount(<AssignScope data={APPROVERS} />, "/approvers");
    await userEvent.click(await screen.findByRole("button", { name: "Assign an approver" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an approver" });
    expect(within(dialog).getByLabelText("Approver")).toHaveValue(HUMAN);
    expect(within(dialog).getByLabelText("Canonical target")).toHaveValue(TARGET);
    expect(within(dialog).getByLabelText("Action")).toHaveValue("endpoint.isolate");
    await userEvent.selectOptions(within(dialog).getByLabelText("Action"), "endpoint.lift_isolation");
    expect(within(dialog).getByRole("button", { name: "Assign" })).toBeEnabled();
  });

  it("says when nothing is assigned", async () => {
    mount(<ApproversList data={{ ...APPROVERS, assignments: [] }} />, "/approvers");
    expect(await screen.findByRole("status")).toHaveTextContent("No active assignments.");
  });
});
