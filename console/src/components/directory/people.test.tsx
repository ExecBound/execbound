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

import type { AccessPage, PeoplePage, PersonDetail, PersonRow } from "../../api/types.gen";
import { DEFAULT_PEOPLE_SEARCH, NewApprover, parsePeopleSearch, PeopleList } from "./PeopleList";
import { PersonDetailView } from "./PersonDetail";
import { StepUpHost } from "../StepUpHost";
import { answerWith } from "../../test/page";
import { clearToasts } from "../../lib/toast";

afterEach(() => { vi.unstubAllGlobals(); clearToasts(); });

const HUMAN = "22222222-2222-2222-2222-222222222222";
const ADMIN = "33333333-3333-3333-3333-333333333333";
const GONE = "44444444-4444-4444-4444-444444444444";
const TARGET = "55555555-5555-5555-5555-555555555555";
const LIVE = "66666666-6666-6666-6666-666666666666";
const SESSION = "77777777-7777-7777-7777-777777777777";
const REJOINED = "88888888-8888-8888-8888-888888888888";

function row(overrides: Partial<PersonRow>): PersonRow {
  return {
    principal_id: HUMAN,
    kind: "HUMAN_APPROVER",
    active: true,
    label: null,
    email: null,
    number: 1,
    created_at: "2026-09-10T08:00:00Z",
    deactivated_at: null,
    replaced_by: null,
    live: 1,
    sessions: 0,
    last_sign_in: null,
    scopes: 1,
    ...overrides,
  };
}

const PAGE: PeoplePage = {
  people: [
    row({ label: "Dana Reyes <script>alert(1)</script>", number: 2, sessions: 2, last_sign_in: "2026-09-19T14:02:11Z" }),
    row({ principal_id: ADMIN, kind: "ADMIN", label: "A. Rivera", number: 1, scopes: 0, sessions: 1, live: 1 }),
    row({ principal_id: GONE, number: 3, active: false, live: 0, scopes: 2, deactivated_at: "2026-09-18T00:00:00Z" }),
  ],
};

const APPROVER: PersonDetail = {
  person: { principal_id: HUMAN, kind: "HUMAN_APPROVER", active: true, label: "Dana Reyes", number: 2, created_at: "2026-09-10T08:00:00Z", deactivated_at: null, replaced_by: null },
  sign_in: { link: null, invitation: null, email: "dana@example.com", has_password: true, pending_until: null, identities: [] },
  credentials: [
    { credential_id: LIVE, issued_at: "2026-09-19T08:00:00Z", expires_at: "2026-09-19T16:00:00Z", revoked_at: null, state: "live", failures: 0 },
  ],
  scopes: [{ canonical_target_id: TARGET, action: "endpoint.isolate", labels: "ws25" }],
  targets: [{ canonical_target_id: TARGET, labels: "ws25" }],
  actions: ["endpoint.isolate", "endpoint.lift_isolation"],
  sessions: [{ session_id: SESSION, created_at: "2026-09-19T14:00:00Z", expires_at: "2026-09-19T22:00:00Z", label: "Safari on iPhone" }],
  history: {
    decisions: [{ decided_at: "2026-09-19T14:05:00Z", approval: "abcd1234", approval_id: "abcd1234-0000-4000-8000-000000000001", execution_id: null, action: "endpoint.isolate", target: "55555555", decision: "denied" }],
    sign_ins: [{ occurred_at: "2026-09-19T14:00:00Z", session: "77777777", credential: "66666666", device: "Safari on iPhone", state: "active" }],
    events: [],
  },
  history_limit: 20,
  is_self: false,
};

const ME: PersonDetail = {
  ...APPROVER,
  person: { principal_id: ADMIN, kind: "ADMIN", active: true, label: null, number: 1, created_at: null, deactivated_at: null, replaced_by: null },
  sign_in: { ...APPROVER.sign_in, email: null },
  scopes: [],
  targets: [],
  history: {
    decisions: [],
    sign_ins: APPROVER.history.sign_ins,
    events: [
      { occurred_at: "2026-09-19T14:10:00Z", words: "Deactivated", subject: "22222222", label: "Dana Reyes" },
      { occurred_at: "2026-09-19T14:00:00Z", words: "Changed the enforcement mode to OBSERVE", subject: "", label: null },
    ],
  },
  is_self: true,
};

const ACCESS: AccessPage = {
  roles: [
    { id: "administrator", name: "Administrator", description: "Workspace administration", permissions: [], scopes: ["WORKSPACE"] },
    { id: "policy_manager", name: "Policy manager", description: "Manage policies", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
    { id: "approver", name: "Approver", description: "Review assigned requests", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
    { id: "viewer", name: "Viewer", description: "Read activity", permissions: [], scopes: ["WORKSPACE", "SPACE"] },
  ],
  spaces: [{ space_id: TARGET, name: "Production" }],
  groups: [],
  users: [
    { principal_id: HUMAN, kind: "HUMAN_APPROVER", active: true, label: "Dana Reyes", email: "dana@example.com", number: 2, managed: true, direct_roles: [{ role: "policy_manager", space_id: TARGET }], inherited_roles: [{ role: "approver", space_id: TARGET, group_id: GONE, group_name: "SOC reviewers" }] },
    { principal_id: ADMIN, kind: "ADMIN", active: true, label: "A. Rivera", email: null, number: 1, managed: true, direct_roles: [{ role: "viewer", space_id: null }], inherited_roles: [] },
  ],
};

function userAccess() {
  const user = ACCESS.users[0];
  if (user === undefined) throw new Error("The synthetic user is missing");
  return user;
}

function setupSection() {
  const section = screen.getByRole("heading", { name: "Account setup" }).closest("section");
  if (section === null) throw new Error("The setup section is missing");
  return section;
}

function mount(element: ReactNode, initial = "/people", detailElement = element) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/people", element),
      page("/people/$personId", detailElement),
      page("/settings", <p>Settings</p>),
      page("/activity", <p>Activity</p>),
      page("/agents/$agentId", <p>Agent</p>),
      page("/policy/$bundleId", <p>Policy</p>),
    ]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("the people list", () => {
  it("shows actual scoped direct and inherited roles with one shared access read, without inferring Administrator from account kind", async () => {
    const calls = answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PeopleList data={PAGE} search={DEFAULT_PEOPLE_SEARCH} onSearch={vi.fn()} />);
    const table = await screen.findByRole("table", { name: /Users matching/ });
    expect(await within(table).findByText("Policy manager · Production")).toBeInTheDocument();
    expect(within(table).getByText(/Approver · Production.*SOC reviewers/)).toBeInTheDocument();
    const adminRow = within(table).getByRole("link", { name: "A. Rivera" }).closest("tr");
    expect(adminRow).toHaveTextContent("Viewer · Workspace");
    expect(adminRow).not.toHaveTextContent("Administrator");
    expect(calls.filter((call) => call.path.endsWith("/access"))).toHaveLength(1);
    expect(screen.getByRole("link", { name: "Groups & roles" })).toHaveAttribute("href", "/access");
    expect(screen.getByRole("link", { name: "Approval rules" })).toHaveAttribute("href", "/approvers");
    await userEvent.click(within(table).getByRole("button", { name: "Edit roles for Dana Reyes" }));
    expect(await screen.findByRole("dialog", { name: "Roles for Dana Reyes" })).toBeInTheDocument();
  });

  it("shows unknown role access after a read failure instead of falling back to a stored account kind", async () => {
    answerWith({ "GET /api/console/v1/access": { status: 403, body: { code: "FORBIDDEN", detail: "Access unavailable" } } });
    mount(<PeopleList data={PAGE} search={DEFAULT_PEOPLE_SEARCH} onSearch={vi.fn()} />);
    const table = await screen.findByRole("table", { name: /Users matching/ });
    await waitFor(() => { expect(within(table).getAllByText("Unavailable").length).toBeGreaterThan(0); });
    expect(table).not.toHaveTextContent("Administrator");
    expect(within(table).queryByRole("button", { name: /Edit roles/ })).toBeNull();
  });
  it("lists humans with their counts, links each by id, and shows scopes for approvers only", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    const onSearch = vi.fn();
    mount(<PeopleList data={PAGE} search={DEFAULT_PEOPLE_SEARCH} onSearch={onSearch} />);
    const table = await screen.findByRole("table", { name: /Users matching/ });
    await within(table).findByText("Policy manager · Production");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0] ?? table).getByRole("link", { name: "Dana Reyes <script>alert(1)</script>" })).toHaveAttribute(
      "href",
      `/people/${HUMAN}`,
    );
    expect(document.querySelector("script")).toBeNull();
    expect(rows[0]).toHaveTextContent("Policy manager");
    expect(rows[0]).toHaveTextContent("2026-09-19 14:02 UTC");
    expect(within(rows[0] ?? table).getAllByRole("cell")[6]).toHaveTextContent("1");
    expect(rows[1]).toHaveTextContent("Viewer");
    expect(within(rows[1] ?? table).getAllByRole("cell")[6]).toHaveTextContent("0");
    expect(within(rows[2] ?? table).getByRole("link", { name: "User 3" })).toHaveAttribute("href", `/people/${GONE}`);
    expect(within(rows[2] ?? table).getByText("Deactivated")).toHaveClass("badge-stale");
    await userEvent.selectOptions(screen.getByLabelText("Sign-in management"), "ADMIN");
    expect(onSearch).toHaveBeenCalledWith({ kind: "ADMIN" });
    expect(parsePeopleSearch({ state: "all", kind: "AGENT", foo: 1 })).toEqual({ state: "all", kind: "any" });
  });

  it("names a person without a label by their email, else by their number, where the id prefix was", async () => {
    const unlabelled = { ...userAccess(), label: null, email: "dana@example.com", number: 3 };
    answerWith({ "GET /api/console/v1/access": { body: { ...ACCESS, users: [unlabelled] } } });
    const people: PeoplePage = {
      people: [
        row({ email: "dana@example.com", number: 3 }),
        row({ principal_id: GONE, number: 5 }),
      ],
    };
    mount(<PeopleList data={people} search={DEFAULT_PEOPLE_SEARCH} onSearch={vi.fn()} />);
    const table = await screen.findByRole("table", { name: /Users matching/ });
    const [emailed, bare] = within(table).getAllByRole("row").slice(1);
    if (emailed === undefined || bare === undefined) throw new Error("The rows are missing");
    // The email names the person and their number sits beside it, where the id prefix was.
    expect(within(emailed).getByRole("link", { name: "dana@example.com" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(within(emailed).getAllByRole("cell")[0]).toHaveTextContent(/^dana@example\.com User 3$/);
    // With neither a label nor an email the number is the name, once.
    expect(within(bare).getByRole("link", { name: "User 5" })).toHaveAttribute("href", `/people/${GONE}`);
    expect(within(bare).getAllByRole("cell")[0]).toHaveTextContent(/^User 5$/);
    expect(table).not.toHaveTextContent(/unlabelled/i);
    expect(table).not.toHaveTextContent(HUMAN.slice(0, 8));
    expect(table).not.toHaveTextContent(GONE.slice(0, 8));
    await userEvent.click(await within(table).findByRole("button", { name: "Edit roles for dana@example.com" }));
    expect(await screen.findByRole("dialog", { name: "Roles for dana@example.com" })).toBeInTheDocument();
  });

  it("marks an entry a re-invitation replaced as rejoined rather than merely deactivated", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    const replaced = row({ principal_id: GONE, label: "Earlier entry", active: false, deactivated_at: "2026-09-18T00:00:00Z", replaced_by: REJOINED });
    mount(<PeopleList data={{ people: [replaced] }} search={DEFAULT_PEOPLE_SEARCH} onSearch={vi.fn()} />);
    const table = await screen.findByRole("table", { name: /Users matching/ });
    const entry = within(table).getByRole("link", { name: "Earlier entry" }).closest("tr");
    if (entry === null) throw new Error("The replaced row is missing");
    expect(within(entry).getByText("Rejoined as a new entry")).toHaveClass("badge-stale");
    expect(within(entry).queryByText("Deactivated")).toBeNull();
  });
});

describe("the person detail", () => {
  it.each(["direct", "group"])("protects a HUMAN account promoted to Administrator through %s roles", async (source) => {
    const promoted = { ...userAccess(), direct_roles: source === "direct" ? [{ role: "administrator" as const, space_id: null }] : [], inherited_roles: source === "group" ? [{ role: "administrator" as const, space_id: null, group_id: GONE, group_name: "Workspace owners" }] : [] };
    answerWith({ "GET /api/console/v1/access": { body: { ...ACCESS, users: [promoted] } } });
    mount(<PersonDetailView detail={APPROVER} />, `/people/${HUMAN}`);
    await screen.findByText(source === "direct" ? "Administrator · Workspace" : /Administrator · Workspace.*Workspace owners/);
    expect(screen.queryByRole("button", { name: "Create password setup code" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Save the address" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deactivate this user" })).toBeNull();
    await userEvent.click(screen.getByText("Advanced access details"));
    expect(screen.queryByRole("button", { name: /^Revoke/ })).toBeNull();
    expect(screen.getByText(/installation owner manages this account’s directory/)).toBeInTheDocument();
  });

  it("does not ask a Viewer to configure review authority", async () => {
    const viewer = { ...userAccess(), direct_roles: [{ role: "viewer" as const, space_id: TARGET }], inherited_roles: [] };
    answerWith({ "GET /api/console/v1/access": { body: { ...ACCESS, users: [viewer] } } });
    mount(<PersonDetailView detail={{ ...APPROVER, scopes: [] }} />, `/people/${HUMAN}`);
    await screen.findByText("Viewer · Production");
    const setup = setupSection();
    expect(setup).toHaveTextContent("Review access is optional");
    expect(setup).not.toHaveTextContent("Assign review permissions");
  });

  it("shows group review roles separately from individual assignments without claiming rule eligibility", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PersonDetailView detail={{ ...APPROVER, scopes: [] }} />, `/people/${HUMAN}`);
    await screen.findByText(/Approver · Production.*SOC reviewers/);
    const setup = setupSection();
    expect(setup).toHaveTextContent("Approver via SOC reviewers");
    expect(setup).toHaveTextContent("Individual review assignments: none assigned");
    expect(within(setup).getByRole("link", { name: "Open Approval rules" })).toHaveAttribute("href", "/approvers");
    expect(setup).not.toHaveTextContent("Assign review permissions");
  });

  it("shows scoped role sources and saves direct role edits through the shared editor", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      [`POST /api/console/v1/access/users/${HUMAN}/roles`]: { body: { changed: true } },
    });
    mount(<PersonDetailView detail={APPROVER} />, `/people/${HUMAN}`);
    const roles = await screen.findByRole("region", { name: "Roles and access" });
    expect(await within(roles).findByText("Policy manager · Production")).toBeInTheDocument();
    expect(within(roles).getByText(/Approver · Production.*SOC reviewers/)).toBeInTheDocument();
    await userEvent.click(within(roles).getByRole("button", { name: "Edit roles" }));
    const dialog = await screen.findByRole("dialog", { name: "Roles for Dana Reyes" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Role 1"), "viewer");
    await userEvent.type(within(dialog).getByLabelText("Reason for this access change"), "Read-only assignment");
    await userEvent.click(within(dialog).getByRole("button", { name: "Save roles" }));
    await waitFor(() => { expect(calls.some((call) => call.method === "POST")).toBe(true); });
    expect(calls.find((call) => call.method === "POST")?.body).toEqual({ grants: [{ role: "viewer", space_id: TARGET }], reason: "Read-only assignment" });
  });
  it("gives an approver identity, sessions, credentials, scopes, history and deactivation", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PersonDetailView detail={APPROVER} />, `/people/${HUMAN}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Dana Reyes" })).toBeInTheDocument();
    await screen.findByText("Policy manager · Production");
    for (const section of ["Account setup", "Identity", "Sessions", "Review permissions", "History", "Deactivate"]) {
      expect(screen.getByRole("heading", { level: 2, name: section })).toBeInTheDocument();
    }
    expect(within(screen.getByRole("table", { name: "Active sessions of this user." })).getByText("Safari on iPhone")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "End all sessions" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Issue credential" })).toBeNull();
    expect(screen.getByText("Advanced access details").closest("details")).not.toHaveAttribute("open");
    await userEvent.click(screen.getByText("Advanced access details"));
    expect(screen.getByRole("button", { name: `Revoke ${LIVE.slice(0, 8)}` })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unassign endpoint.isolate on 55555555" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Assign" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: /decisions of this user/ })).toHaveTextContent("denied");
    expect(screen.queryByRole("table", { name: /administrative events/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Deactivate this user" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Deactivate this user" }));
    const dialog = await screen.findByRole("dialog", { name: "Deactivate this user?" });
    expect(within(dialog).getByRole("button", { name: "Deactivate" })).toBeDisabled();
  });

  it("gives an administrator owner tooling, their events, review scopes and no deactivation", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PersonDetailView detail={ME} />, `/people/${ADMIN}`);
    expect(await screen.findByRole("heading", { level: 1, name: "User 1" })).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/unlabelled/i);
    expect(screen.getByText("owner tooling")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Issue credential" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Revoke/ })).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "Review permissions" })).toBeInTheDocument();
    expect(screen.getByText(/Administrator access does not grant review permission automatically/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Deactivate this user" })).toBeNull();
    expect(screen.queryByRole("button", { name: "End all sessions" })).toBeNull();
    expect(screen.getAllByRole("link", { name: "My account" })[0]).toHaveAttribute("href", "/settings");
    const events = screen.getByRole("table", { name: /administrative events/ });
    expect(events).toHaveTextContent("Deactivated");
    expect(events).toHaveTextContent("22222222 · Dana Reyes");
    expect(events).toHaveTextContent("this tenant");
    expect(screen.getByText(/created before labels/)).toBeInTheDocument();
  });

  it("titles a person without a label by their email, with their number where the id prefix was", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PersonDetailView detail={{ ...APPROVER, person: { ...APPROVER.person, label: null, number: 3 } }} />, `/people/${HUMAN}`);
    expect(await screen.findByRole("heading", { level: 1, name: "dana@example.com" })).toBeInTheDocument();
    expect(document.querySelector(".meta")).toHaveTextContent("Back to Users · User 3 · created");
    expect(document.querySelector(".meta")).not.toHaveTextContent(HUMAN.slice(0, 8));
    expect(document.body).not.toHaveTextContent(/unlabelled/i);
    // One quiet field under the heading offers a name (#678); the setup line points to it.
    expect(screen.getByRole("form", { name: "Name this person" })).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toHaveAttribute("maxlength", "80");
    expect(screen.getByText("Named account: not yet; name them above")).toBeInTheDocument();
  });

  it("offers no name prompt for a person who has a label", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(<PersonDetailView detail={APPROVER} />, `/people/${HUMAN}`);
    expect(await screen.findByRole("heading", { level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Name this person" })).toBeNull();
  });

  it("asks for the step-up a person's label needs before saving a name from the prompt (#678)", async () => {
    let verified = false;
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      [`POST /api/console/v1/people/${HUMAN}/label`]: () =>
        verified
          ? { body: { ...APPROVER, person: { ...APPROVER.person, label: "Dana Reyes" } } }
          : { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } },
      "POST /api/console/v1/session/verify": () => {
        verified = true;
        return { body: { csrf_token: "rotated-token" } };
      },
    });
    const rootRoute = createRootRoute({ component: () => <Outlet /> });
    const router = createRouter({
      routeTree: rootRoute.addChildren([
        createRoute({
          getParentRoute: () => rootRoute,
          path: "/people/$personId",
          component: () => (
            <>
              <PersonDetailView detail={{ ...APPROVER, person: { ...APPROVER.person, label: null, number: 3 } }} />
              <StepUpHost />
            </>
          ),
        }),
      ]),
      history: createMemoryHistory({ initialEntries: [`/people/${HUMAN}`] }),
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    await userEvent.type(await screen.findByLabelText("Name"), "Dana Reyes");
    await userEvent.click(screen.getByRole("button", { name: "Save name" }));
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    await waitFor(() => {
      expect(calls.filter((call) => call.method === "POST" && call.path.endsWith("/label"))).toHaveLength(2);
    });
    const [first] = calls.filter((call) => call.path.endsWith("/label"));
    expect(first?.body).toEqual({ label: "Dana Reyes" });
  });

  it("offers a deactivated approver no forms and a Reactivate", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    const detail: PersonDetail = {
      ...APPROVER,
      person: { ...APPROVER.person, active: false, deactivated_at: "2026-09-19T15:00:00Z" },
      credentials: [{ ...APPROVER.credentials[0], credential_id: LIVE, state: "revoked", revoked_at: "2026-09-19T15:00:00Z" } as PersonDetail["credentials"][number]],
      sessions: [],
    };
    mount(<PersonDetailView detail={detail} />, `/people/${HUMAN}`);
    expect(await screen.findByRole("button", { name: "Reactivate this user" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Issue credential" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Assign" })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Unassign/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "End all sessions" })).toBeNull();
    expect(screen.getByText(/deactivated 2026-09-19 15:00 UTC/)).toBeInTheDocument();
  });

  it.each(["standard", "administrator"])("shows a %s entry a re-invitation replaced as rejoined, with a link to the new entry and no Reactivate", async (was) => {
    const earlier = was === "administrator"
      ? { ...userAccess(), active: false, direct_roles: [{ role: "administrator" as const, space_id: null }], inherited_roles: [] }
      : { ...userAccess(), active: false };
    answerWith({ "GET /api/console/v1/access": { body: { ...ACCESS, users: [earlier] } } });
    const detail: PersonDetail = {
      ...APPROVER,
      person: { ...APPROVER.person, active: false, deactivated_at: "2026-09-19T15:00:00Z", replaced_by: REJOINED },
      sessions: [],
    };
    mount(<PersonDetailView detail={detail} />, `/people/${HUMAN}`);
    const card = (await screen.findByRole("heading", { level: 2, name: "Rejoined" })).closest("section");
    if (card === null) throw new Error("The rejoined section is missing");
    expect(card).toHaveTextContent("This person rejoined through an invitation and now has a new entry in this workspace. Manage their access there.");
    expect(within(card).getByRole("link", { name: "Open their new entry" })).toHaveAttribute("href", `/people/${REJOINED}`);
    expect(screen.getAllByText("Rejoined as a new entry")[0]).toHaveClass("badge-stale");
    expect(screen.queryByText("Deactivated")).toBeNull();
    expect(screen.queryByRole("button", { name: "Reactivate this user" })).toBeNull();
    expect(screen.queryByRole("heading", { level: 2, name: "Reactivate" })).toBeNull();
    expect(document.body).not.toHaveTextContent(/Reactivate this account|Restore access/);
  });
});

describe("named account setup", () => {
  it("refreshes cached access after account creation so the new user's roles are available immediately", async () => {
    let created = false;
    answerWith({
      "GET /api/console/v1/access": () => ({ body: created ? ACCESS : { ...ACCESS, users: [] } }),
      "POST /api/console/v1/people": () => { created = true; return { body: { principal_id: HUMAN } }; },
      [`POST /api/console/v1/people/${HUMAN}/email`]: { body: APPROVER },
    });
    mount(<><NewApprover /><PeopleList data={{ people: [] }} search={DEFAULT_PEOPLE_SEARCH} onSearch={vi.fn()} /></>, "/people", <PersonDetailView detail={APPROVER} />);
    await screen.findByRole("table", { name: /Users matching/ });
    await userEvent.click(screen.getByRole("button", { name: "Add user" }));
    await userEvent.type(await screen.findByLabelText("Name (required)"), "Dana Reyes");
    await userEvent.type(screen.getByLabelText("Sign-in email (required)"), "dana@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    const roles = await screen.findByRole("region", { name: "Roles and access" });
    expect(await within(roles).findByText("Policy manager · Production")).toBeInTheDocument();
    expect(within(roles).getByRole("button", { name: "Edit roles" })).toBeEnabled();
  });

  it("creates the account and saves its address through protected operations without issuing a bearer credential", async () => {
    const seen = answerWith({
      "POST /api/console/v1/people": { body: { principal_id: HUMAN } },
      [`POST /api/console/v1/people/${HUMAN}/email`]: { body: APPROVER },
    });
    mount(<NewApprover />);
    await userEvent.click(await screen.findByRole("button", { name: "Add user" }));
    await userEvent.type(screen.getByLabelText("Name (required)"), "Dana Reyes");
    await userEvent.type(screen.getByLabelText("Sign-in email (required)"), "dana@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    await screen.findByRole("button", { name: "Add user" });
    expect(seen.map((request) => request.path)).toEqual(["/api/console/v1/people", `/api/console/v1/people/${HUMAN}/email`]);
    expect(seen[0]?.body).toEqual({ label: "Dana Reyes" });
    expect(seen[1]?.body).toEqual({ email: "dana@example.com" });
    expect(seen.every((request) => request.headers.get("x-csrf-token") === "token-under-test")).toBe(true);
  });

  it("retries only the address after a partial setup failure", async () => {
    let attempts = 0;
    const seen = answerWith({
      "POST /api/console/v1/people": { body: { principal_id: HUMAN } },
      [`POST /api/console/v1/people/${HUMAN}/email`]: () => ++attempts === 1
        ? { status: 409, body: { code: "CONFLICT" } } : { body: APPROVER },
    });
    mount(<NewApprover />);
    await userEvent.click(await screen.findByRole("button", { name: "Add user" }));
    await userEvent.type(screen.getByLabelText("Name (required)"), "Dana Reyes");
    await userEvent.type(screen.getByLabelText("Sign-in email (required)"), "dana@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("The account exists");
    expect(screen.getByLabelText("Name (required)")).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Save sign-in address" }));
    await screen.findByRole("button", { name: "Add user" });
    expect(seen.filter((request) => request.path === "/api/console/v1/people")).toHaveLength(1);
    expect(attempts).toBe(2);
  });

  it("provides password setup and explicit review assignment with CSRF on each operation", async () => {
    const seen = answerWith({
      "GET /api/console/v1/tenant/sign-in": { body: { provider: null } },
      "GET /api/console/v1/access": { body: ACCESS },
      [`POST /api/console/v1/people/${HUMAN}/password-link`]: { body: {
        code: "synthetic-setup-code", address: "https://app.example/set-password", reset_id: LIVE,
        principal_id: HUMAN, expires_at: "2026-09-23T10:00:00Z",
      } },
      [`POST /api/console/v1/people/${HUMAN}/scopes/assign`]: { body: APPROVER },
    });
    mount(<PersonDetailView detail={{ ...APPROVER, sign_in: { ...APPROVER.sign_in, has_password: false }, scopes: [] }} />, `/people/${HUMAN}`);
    await userEvent.click(await screen.findByRole("button", { name: "Create password setup code" }));
    expect(await screen.findByLabelText("Page to open")).toHaveValue("https://app.example/set-password");
    await userEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    await userEvent.click(screen.getByRole("button", { name: "Assign" }));
    expect(seen.find((request) => request.path.endsWith("/scopes/assign"))?.body).toEqual({ target: TARGET, action: "endpoint.isolate" });
    expect(seen.filter((request) => request.method === "POST").every((request) => request.headers.get("x-csrf-token") === "token-under-test")).toBe(true);
    expect(seen.some((request) => request.path.includes("credentials/issue"))).toBe(false);
  });
});

describe("second-factor status and the history (AK9, AK12)", () => {
  const EXECUTION = "e0e0e0e0-0000-4000-8000-000000000001";
  const BUNDLE = "b0b0b0b0-0000-4000-8000-000000000001";
  const AGENT = "a0a0a0a0-0000-4000-8000-000000000001";
  const SPACE = "c0c0c0c0-0000-4000-8000-000000000001";

  it("says in words who has a second factor on Users and on the person page", async () => {
    const [first, second] = PAGE.people;
    if (first === undefined || second === undefined) throw new Error("fixture");
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    mount(
      <PeopleList
        data={{ ...PAGE, people: [{ ...first, second_factor: true }, { ...second, second_factor: false }] }}
        search={DEFAULT_PEOPLE_SEARCH}
        onSearch={vi.fn()}
      />,
    );
    const table = await screen.findByRole("table", { name: /Users matching the filters/ });
    expect(within(table).getByRole("columnheader", { name: "Second factor" })).toBeInTheDocument();
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("Enrolled");
    expect(rows[1]).toHaveTextContent("None");
  });

  it("labels the three histories and links what the reader may open", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    const detail: PersonDetail = {
      ...APPROVER,
      person: { ...APPROVER.person, second_factor: true },
      history: {
        ...APPROVER.history,
        decisions: [
          { decided_at: "2026-09-19T14:05:00Z", approval: "abcd1234", approval_id: "abcd1234-0000-4000-8000-000000000001", execution_id: EXECUTION, action: "endpoint.isolate", target: "55555555", decision: "approved" },
          { decided_at: "2026-09-19T14:04:00Z", approval: "dcba4321", approval_id: "dcba4321-0000-4000-8000-000000000001", execution_id: null, action: "endpoint.isolate", target: "55555555", decision: "denied" },
        ],
      },
    };
    mount(<PersonDetailView detail={detail} />, `/people/${HUMAN}`);
    await screen.findByRole("heading", { level: 1, name: "Dana Reyes" });
    const signIn = screen.getByRole("heading", { level: 2, name: "Sign-in" }).closest("section");
    if (signIn === null) throw new Error("No Sign-in card");
    expect(within(signIn).getByText("Second factor").nextSibling).toHaveTextContent("Enrolled");
    for (const name of ["Decisions", "Sign-ins"]) {
      expect(screen.getByRole("heading", { level: 3, name })).toBeVisible();
    }
    expect(screen.queryByRole("heading", { level: 3, name: "Administrative changes" })).toBeNull();
    const decisions = screen.getByRole("table", { name: /decisions of this user/ });
    expect(within(decisions).getByRole("link", { name: "abcd1234" })).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
    expect(within(decisions).queryByRole("link", { name: "dcba4321" })).toBeNull();
    expect(decisions).toHaveTextContent("dcba4321");
  });

  it("links an administrator's bundle, agent and person subjects, and leaves a space and a credential as text", async () => {
    answerWith({ "GET /api/console/v1/access": { body: ACCESS } });
    const event = (words: string, subject_id: string, kind: "bundle" | "principal" | "space" | "credential", extra = {}) => ({
      occurred_at: "2026-09-19T14:10:00Z", words, subject: subject_id.slice(0, 8), label: null, subject_id, subject_kind: kind, ...extra,
    });
    const detail: PersonDetail = {
      ...ME,
      history: {
        ...ME.history,
        events: [
          event("Activated policy bundle", BUNDLE, "bundle"),
          { ...event("Labelled", AGENT, "principal", { subject_principal_kind: "AGENT", subject_number: 7 }), label: "<img src=x onerror=alert(1)>" },
          event("Deactivated", HUMAN, "principal", { subject_principal_kind: "HUMAN_APPROVER", subject_number: 2 }),
          event("Created space", SPACE, "space"),
          event("Issued credential", LIVE, "credential"),
        ],
      },
    };
    mount(<PersonDetailView detail={detail} />, `/people/${ADMIN}`);
    await screen.findByRole("heading", { level: 1, name: "User 1" });
    expect(screen.getByRole("heading", { level: 3, name: "Administrative changes" })).toBeVisible();
    const events = screen.getByRole("table", { name: /administrative events/ });
    expect(within(events).getByRole("link", { name: "Policy version b0b0b0b0" })).toHaveAttribute("href", `/policy/${BUNDLE}`);
    expect(within(events).getByRole("link", { name: "<img src=x onerror=alert(1)>" })).toHaveAttribute("href", `/agents/${AGENT}`);
    expect(document.querySelector("img")).toBeNull();
    expect(within(events).getByRole("link", { name: "User 2" })).toHaveAttribute("href", `/people/${HUMAN}`);
    expect(events).toHaveTextContent(SPACE.slice(0, 8));
    expect(events).toHaveTextContent(LIVE.slice(0, 8));
    expect(within(events).getAllByRole("link")).toHaveLength(3);
  });
});
