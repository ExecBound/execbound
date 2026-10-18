// SPDX-License-Identifier: AGPL-3.0-only
// The palette's Recent, Commands, hint, name and all-spaces retry (NV10 to NV13, #678). A command
// only opens what a button would open: no key, no Enter, performs anything by itself.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, useRouterState } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readApprovalQueryKey } from "../../api/@tanstack/react-query.gen";
import type { SearchResult, SearchView } from "../../api/types.gen";
import { detail as approvalDetail } from "../../approvals/fixtures";
import { forgetCommands } from "../../lib/commands";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../../lib/session";
import { ShellActionsContext, type ShellActions } from "../../shell/actions";
import { heldPaletteQuery, releasePaletteQuery } from "../../shell/reopen";
import { FOOTER, NAVIGATION } from "../../shell/navigation";
import { Shell } from "../../shell/Shell";
import { NewAgent } from "../directory/NewAgent";
import { called, json, serve, type Call } from "../../test/api";
import { PageHeading } from "./PageHeading";
import CommandPalette, { searchHint } from "./CommandPalette";

const TENANT = "7f8e9d0c-0000-4000-8000-000000000003";
const ME = "dddddddd-0000-4000-8000-00000000000a";
const FOUND = "5c2f91d3-0000-4000-8000-000000000002";
const GONE = "5c2f91d3-0000-4000-8000-000000000003";
const APPROVAL = "4b1e90c2-0000-4000-8000-000000000001";

const ALL = ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"];
const admin: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ALL,
  tenant: { id: TENANT, name: "Acme SOC", detail: "" },
  person: { label: "A. Rivera", detail: "", initials: "AR", id: ME },
  csrf: "token",
};
const approver: SessionSummary = { ...admin, role: "APPROVER", permissions: ["console.read", "approvals.decide"] };
const accessOnly: SessionSummary = { ...admin, role: "POLICY_MANAGER", permissions: ["console.read", "access.manage", "policy.manage"] };

const record: SearchResult = {
  kind: "execution",
  id: FOUND,
  label: "Isolate endpoint on dc01",
  detail: "Request 5c2f91d3",
  state: "DENIED",
  state_label: "Denied",
  execution_id: FOUND,
};
const person: SearchResult = { kind: "person", id: "d0000000-0000-4000-8000-000000000004", label: "User 3", detail: "User", state: null, state_label: null, execution_id: null };

function searches(request: Request): Response {
  const q = new URL(request.url).searchParams.get("q") ?? "";
  const results = q === FOUND ? [record] : q.toLowerCase() === "user 3" ? [person] : [];
  const view: SearchView = { query: q, results };
  return json(view);
}

function remember(items: unknown[]): void {
  window.localStorage.setItem(`eb.recent.v1.${TENANT}.${ME}`, JSON.stringify(items));
}

const noActions: ShellActions = {
  openPalette: vi.fn(),
  openShortcuts: vi.fn(),
  openStop: vi.fn(),
  openNotifications: vi.fn(),
  openSheet: vi.fn(),
};

/** The palette as the shell renders it, with the router's own address for the page. */
function RoutedPalette() {
  const href = useRouterState({ select: (state) => state.location.href });
  return <CommandPalette open onClose={() => undefined} href={href} />;
}

/** The palette alone, open over a page at `initial`. */
function palette(session: SessionSummary, initial = "/", actions: ShellActions = noActions, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const calls = serve({ "/api/console/v1/search": searches, "/api/console/v1/session/space": {}, "/api/console/v1/spaces": { items: [], next_cursor: null, administrator: true, all_spaces: true, current_space_id: null } });
  const root = createRootRoute({
    component: () => (
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={session}>
          <ShellActionsContext.Provider value={actions}>
            <Outlet />
            <RoutedPalette />
          </ShellActionsContext.Provider>
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  const pages = [
    ...[...NAVIGATION, ...FOOTER].map((entry) => createRoute({ getParentRoute: () => root, path: entry.to, component: () => null })),
    createRoute({ getParentRoute: () => root, path: "/approvals/$approvalId", component: () => null }),
    createRoute({ getParentRoute: () => root, path: "/people/$personId", component: () => null }),
  ];
  const router = createRouter({ routeTree: root.addChildren(pages), history: createMemoryHistory({ initialEntries: [initial] }) });
  render(<RouterProvider router={router} />);
  return { calls, router };
}

/** The whole shell, with Agent connections' real Add agent button on its page. */
function shell(session: SessionSummary) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const calls = serve({ "/api/console/v1/search": searches });
  const root = createRootRoute({
    component: () => (
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={session}>
          <Shell>
            <Outlet />
          </Shell>
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  const pages = [...NAVIGATION, ...FOOTER].map((entry) =>
    createRoute({
      getParentRoute: () => root,
      path: entry.to,
      component: () => (
        <>
          <PageHeading title={entry.label} />
          {entry.to === "/agents" ? <NewAgent /> : null}
        </>
      ),
    }),
  );
  const router = createRouter({ routeTree: root.addChildren(pages), history: createMemoryHistory({ initialEntries: ["/"] }) });
  render(<RouterProvider router={router} />);
  return { calls, router };
}

const commandNames = async () => {
  const group = await screen.findByRole("group", { name: "Commands" });
  return within(group).getAllByRole("option").map((option) => option.textContent);
};

const posts = (calls: Call[]) => calls.filter((call) => call.method !== "GET");

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  forgetCommands();
});

describe("Recent (NV11, #678)", () => {
  it("lists pages by their label and only the records the scoped search still finds", async () => {
    remember([{ k: "execution", id: GONE }, { k: "page", to: "/agents" }, { k: "execution", id: FOUND }]);
    const { router, calls } = palette(admin);
    const recent = await screen.findByRole("group", { name: "Recent" });
    expect(await within(recent).findByRole("option", { name: /^Isolate endpoint on dc01/ })).toBeInTheDocument();
    expect(within(recent).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "Agent connections",
      "Isolate endpoint on dc01Request 5c2f91d3",
    ]);
    expect(called(calls, "GET", "/api/console/v1/search", `?q=${GONE}`)).toBe(true);
    await userEvent.click(within(recent).getByRole("option", { name: /^Isolate endpoint on dc01/ }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(router.state.location.search).toEqual({ open: FOUND });
  });

  it("never lists a person, and a page this person cannot see is dropped", async () => {
    remember([{ k: "page", to: "/people" }, { k: "page", to: "/policy" }]);
    palette(approver);
    await screen.findByRole("group", { name: "Records" });
    expect(screen.queryByRole("group", { name: "Recent" })).toBeNull();
  });
});

describe("Commands (NV12, #678)", () => {
  it("offers an administrator every command, each opening only what its button opens", async () => {
    remember([{ k: "page", to: "/agents" }]);
    palette(admin);
    expect(await commandNames()).toEqual([
      "Emergency stop…",
      "Add agent",
      "Add user",
      "New space",
      "Issue API key",
      "Keyboard shortcuts",
      "Copy link to this page",
      "Clear recent",
    ]);
  });

  it("offers an approver only the keyboard list, the link and Recent", async () => {
    remember([{ k: "page", to: "/approvals" }]);
    palette(approver);
    expect(await commandNames()).toEqual(["Keyboard shortcuts", "Copy link to this page", "Clear recent"]);
  });

  it("forgets the workspaces this browser opened last with Clear recent", async () => {
    remember([{ k: "page", to: "/approvals" }]);
    window.localStorage.setItem("eb.recent.v1.workspaces", JSON.stringify([TENANT]));
    palette(approver);
    const group = await screen.findByRole("group", { name: "Commands" });
    await userEvent.click(within(group).getByRole("option", { name: "Clear recent" }));
    expect(window.localStorage.getItem("eb.recent.v1.workspaces")).toBeNull();
  });

  it("offers Add user only where Users is a page this person can open", async () => {
    palette(accessOnly);
    const names = await commandNames();
    expect(names).not.toContain("Add user");
    expect(names).not.toContain("Emergency stop…");
  });

  it("reads Resume while a stop is active", async () => {
    palette({ ...admin, stop: { at: "2026-09-19T06:10:00Z", by: ME, reason: "x", byName: "User 1" } });
    expect(await commandNames()).toContain("Resume from the emergency stop…");
  });

  it("opens the stop dialog, and sends nothing, on Enter", async () => {
    const { calls } = shell(admin);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await userEvent.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Search" });
    await userEvent.click(within(dialog).getByRole("option", { name: "Emergency stop…" }));
    expect(await screen.findByRole("dialog", { name: "Activate the emergency stop?" })).toBeInTheDocument();
    expect(posts(calls)).toEqual([]);
  });

  it("goes to Agent connections and opens Add agent, and sends nothing", async () => {
    const { calls, router } = shell(admin);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await userEvent.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Search" });
    await userEvent.click(within(dialog).getByRole("option", { name: "Add agent" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/agents");
    });
    expect(await screen.findByRole("dialog", { name: /^Add agent/ })).toBeInTheDocument();
    expect(posts(calls)).toEqual([]);
  });

  it("copies the page's own address, built by the router", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    palette(admin, `/activity?open=${FOUND}`);
    const group = await screen.findByRole("group", { name: "Commands" });
    await userEvent.click(within(group).getByRole("option", { name: "Copy link to this page" }));
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activity?open=${FOUND}`);
    });
  });

  it("copies an approval's validated link, the workspace's own where it is one", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const client = new QueryClient();
    const scoped = `/workspaces/${TENANT}/approvals/${APPROVAL}`;
    client.setQueryData(readApprovalQueryKey({ path: { approval_id: APPROVAL } }), approvalDetail({ link_path: scoped }));
    palette(admin, `/approvals/${APPROVAL}`, noActions, client);
    const group = await screen.findByRole("group", { name: "Commands" });
    await userEvent.click(within(group).getByRole("option", { name: "Copy link to this page" }));
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(`${window.location.origin}${scoped}`);
    });
  });

  it("falls back to the router's address for a link that fails the grammar, and has none before the read", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const client = new QueryClient();
    client.setQueryData(readApprovalQueryKey({ path: { approval_id: APPROVAL } }), approvalDetail({ link_path: "https://evil.example/approvals/x" }));
    palette(admin, `/approvals/${APPROVAL}`, noActions, client);
    const group = await screen.findByRole("group", { name: "Commands" });
    await userEvent.click(within(group).getByRole("option", { name: "Copy link to this page" }));
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/approvals/${APPROVAL}`);
    });
  });

  it("offers no link on an approval it has not read yet", async () => {
    palette(admin, `/approvals/${APPROVAL}`);
    expect(await commandNames()).not.toContain("Copy link to this page");
  });
});

describe("the empty palette's hint, name and people (NV12, NV15, #678)", () => {
  it("names what the search accepts from each person", () => {
    expect(searchHint(approver)).toBe("Type EB-1042, a case ID, a hostname or a provider id.");
    expect(searchHint({ role: "ADMIN", permissions: ["console.read"] })).toBe(
      "Type EB-1042, a case ID, a hostname, a provider id, or an agent's name or number.",
    );
    expect(searchHint(admin)).toBe("Type EB-1042, a case ID, a hostname, a provider id, an agent's name or number, or User 3.");
  });

  it("is Search without an assistant and Search or ask with one", async () => {
    palette(admin);
    expect(await screen.findByRole("dialog", { name: "Search" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Search")).toBeInTheDocument();
  });

  it("is Search or ask where the deployment has an assistant", async () => {
    palette({ ...admin, assistant: true });
    expect(await screen.findByRole("dialog", { name: "Search or ask" })).toBeInTheDocument();
  });

  it("keeps the server's person result under Records and opens the person's page", async () => {
    const { router } = palette(admin);
    await userEvent.type(await screen.findByPlaceholderText("Search"), "user 3");
    const records = await screen.findByRole("group", { name: "Records" });
    await userEvent.click(await within(records).findByRole("option", { name: /^User 3/ }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/people/${person.id}`);
    });
  });
});

describe("searching all your spaces (NV13, #678)", () => {
  const inSpace: SessionSummary = { ...admin, space: { id: "s-1", name: "Payments", archived: false }, spaces: 2, allSpaces: true };

  it("says which space found nothing and switches to All spaces through the session", async () => {
    const { calls } = palette(inSpace);
    await userEvent.type(await screen.findByPlaceholderText("Search"), "ws99");
    expect(await screen.findByText("No record matches in Payments.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("option", { name: "Search all your spaces" }));
    await waitFor(() => {
      expect(called(calls, "POST", "/api/console/v1/session/space")).toBe(true);
    });
    expect(calls.find((call) => call.method === "POST")?.body).toEqual({ space_id: null });
    // The switch draws the shell again; the words wait for the palette that comes back.
    expect(heldPaletteQuery()).toBe("ws99");
    releasePaletteQuery();
    expect(screen.getByRole("dialog", { name: "Search" })).toBeInTheDocument();
    expect(calls.every((call) => !call.search.includes("space="))).toBe(true);
  });

  it("says your scope, and offers nothing more, outside a space", async () => {
    palette(admin);
    await userEvent.type(await screen.findByPlaceholderText("Search"), "ws99");
    expect(await screen.findByText("No record matches in your scope.")).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Search all your spaces" })).toBeNull();
  });
});
