// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SearchResult, SearchView, SpacePage } from "../../api/types.gen";
import { EditionContext, type Edition, type EditionLink } from "../../edition/context";
import { edition as core } from "../../edition/core";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../../lib/session";
import { called, json, serve } from "../../test/api";
import CommandPalette, { destination, goTo, matchedAlias, matches } from "./CommandPalette";

const SEARCH = "/api/console/v1/search";
const SPACES = "/api/console/v1/spaces";
const SESSION_SPACE = "/api/console/v1/session/space";
const NORTH = "11111111-1111-4111-8111-111111111111";
const SOUTH = "22222222-2222-4222-8222-222222222222";
const SPACE_PAGE: SpacePage = {
  items: [
    { space_id: NORTH, name: "Northwind", detail: null, created_at: "2026-09-01T00:00:00Z", archived_at: null, members: 1, agents: 1, pending: 0, findings: 0 },
    { space_id: SOUTH, name: "Southbank", detail: null, created_at: "2026-09-01T00:00:00Z", archived_at: null, members: 1, agents: 1, pending: 0, findings: 0 },
  ],
  next_cursor: null,
  administrator: true,
  all_spaces: true,
  current_space_id: NORTH,
};
/** A reader of more than one space; the palette's fourth group is theirs. */
const MANY: SessionSummary = {
  ...PLACEHOLDER,
  space: { id: NORTH, name: "Northwind", archived: false },
  spaces: 2,
  allSpaces: true,
};
const TARGET: SearchResult = {
  kind: "target",
  id: "c0000000-0000-4000-8000-000000000001",
  label: "ws01.example",
  detail: "device-01; endpoint, workstation, production",
  state: null,
  state_label: null,
  execution_id: null,
  space_name: "Northwind",
};
const EXECUTION: SearchResult = {
  kind: "execution",
  id: "7c21e04b-0000-4000-8000-000000000001",
  label: "Isolate endpoint on dc01",
  detail: "Request 7c21e04b",
  state: "DENIED",
  state_label: "Denied",
  execution_id: "7c21e04b-0000-4000-8000-000000000001",
};
const APPROVAL: SearchResult = {
  kind: "approval",
  id: "a0000000-0000-4000-8000-000000000002",
  label: "Approval: Isolate endpoint on ws25",
  detail: "Held; approval pending",
  state: "PENDING_APPROVAL",
  state_label: "Held",
  execution_id: "9a11e04b-0000-4000-8000-000000000002",
};
const AGENT: SearchResult = {
  kind: "agent",
  id: "b0000000-0000-4000-8000-000000000003",
  label: "Triage agent A",
  detail: "Agent",
  state: null,
  state_label: null,
  execution_id: null,
};

const PERSON: SearchResult = {
  kind: "person",
  id: "d0000000-0000-4000-8000-000000000004",
  label: "User 3",
  detail: "User",
  state: null,
  state_label: null,
  execution_id: null,
};
const MARKUP_PERSON: SearchResult = {
  ...PERSON,
  id: "d0000000-0000-4000-8000-000000000005",
  label: "<img src=x onerror=alert(1)> user",
  detail: "User 4",
};

function answers(request: Request): Response {
  const q = new URL(request.url).searchParams.get("q") ?? "";
  const results = [TARGET, EXECUTION, APPROVAL, AGENT, PERSON, MARKUP_PERSON].filter(
    (result) => result.label.toLowerCase().includes(q.toLowerCase()) || result.id.startsWith(q),
  );
  const view: SearchView = { query: q, results };
  return json(view);
}

function mount(
  onClose: () => void = () => undefined,
  assistant = false,
  session: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" },
  edition: Edition = core,
) {
  const calls = serve({ [SEARCH]: answers, [SPACES]: SPACE_PAGE, [SESSION_SPACE]: {} });
  const rootRoute = createRootRoute({ component: () => <CommandPalette open onClose={onClose} /> });
  const home = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => null });
  const activity = createRoute({ getParentRoute: () => rootRoute, path: "/activity", component: () => null });
  const people = createRoute({ getParentRoute: () => rootRoute, path: "/people/$personId", component: () => null });
  // Whether the deployment has an assistant arrives with the session (#330), so the palette
  // asks nothing of its own and the Ask group is simply not rendered without one.
  const ask = createRoute({
    getParentRoute: () => rootRoute,
    path: "/ask",
    validateSearch: (search: Record<string, unknown>): { q?: string } =>
      typeof search.q === "string" ? { q: search.q } : {},
    component: () => null,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([home, activity, ask, people]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <EditionContext.Provider value={edition}>
      <SessionContext.Provider value={{ ...session, assistant }}>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </SessionContext.Provider>
    </EditionContext.Provider>,
  );
  return { router, calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("matching a page", () => {
  it("matches the address's own segment and reports the word that matched", () => {
    const keys = { label: "API keys", to: "/credentials-example", aliases: ["API tokens"] };
    expect(matches(keys, "example")).toBe(true);
    expect(matchedAlias(keys, "example")).toBe("credentials-example");
    expect(matchedAlias(keys, "token")).toBe("API tokens");
    expect(matchedAlias(keys, "keys")).toBeUndefined();
    expect(matchedAlias(keys, "")).toBeUndefined();
  });
});

describe("the command palette", () => {
  it("lists the pages, moves with the keyboard, opens on Enter and closes on Escape", async () => {
    const onClose = vi.fn();
    const { router } = mount(onClose);
    const input = await screen.findByPlaceholderText("Search");
    expect(screen.getByRole("dialog", { name: "Search" })).toBeInTheDocument();
    await userEvent.type(input, "activ");
    await waitFor(() => {
      expect(screen.getByText("Activity")).toBeVisible();
    });
    expect(screen.queryByText("Home")).toBeNull();
    await screen.findByText("No record matches in your scope.");
    await userEvent.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(onClose).toHaveBeenCalled();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("moves the selection with the arrow keys and opens the entry it lands on", async () => {
    const onClose = vi.fn();
    const { router } = mount(onClose);
    await screen.findByPlaceholderText("Search");
    // The entries a keyboard can land on, in the order the palette draws them; a disabled
    // line, such as the records hint, is skipped by the selection.
    const entries = () =>
      screen.getAllByRole("option").filter((option) => option.getAttribute("aria-disabled") !== "true");
    const selected = () => entries().findIndex((option) => option.getAttribute("aria-selected") === "true");
    await waitFor(() => {
      expect(entries().length).toBeGreaterThan(2);
    });
    expect(selected()).toBe(0);
    await userEvent.keyboard("{ArrowDown}");
    expect(selected()).toBe(1);
    await userEvent.keyboard("{ArrowDown}");
    expect(selected()).toBe(2);
    await userEvent.keyboard("{ArrowUp}");
    expect(selected()).toBe(1);
    // Down to the first page, past the commands above the pages.
    const firstPage = entries().findIndex((option) => (option.getAttribute("data-value") ?? "").startsWith("page:"));
    for (let step = 1; step < firstPage; step += 1) await userEvent.keyboard("{ArrowDown}");
    expect(selected()).toBe(firstPage);
    const landed = entries()[firstPage]?.getAttribute("data-value") ?? "";
    expect(landed.startsWith("page:")).toBe(true);
    await userEvent.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(landed.slice("page:".length));
    });
    expect(onClose).toHaveBeenCalled();
  });

  it("finds the API keys page under the names people search for", async () => {
    mount();
    const input = await screen.findByPlaceholderText("Search");
    for (const typed of ["API key", "token", "credential"]) {
      await userEvent.clear(input);
      await userEvent.type(input, typed);
      await waitFor(() => {
        expect(screen.getByRole("option", { name: /^API keys/ })).toBeVisible();
      });
    }
  });

  it("finds a page by the words people use for it, and shows the word that matched (NV10, #678)", async () => {
    mount(undefined, false, { ...PLACEHOLDER, role: "ADMIN", permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage"] });
    const input = await screen.findByPlaceholderText("Search");
    for (const [typed, label, word] of [
      ["people", "Users", "People"],
      ["tenant", "Workspace settings", "Tenant"],
      ["approvers", "Approval rules", "Approvers"],
      ["bundle", "Policies", "Bundles"],
      ["mfa", "My account", "MFA"],
      ["credentials", "API keys", "Agent credentials"],
    ] as const) {
      await userEvent.clear(input);
      await userEvent.type(input, typed);
      const option = await screen.findByRole("option", { name: new RegExp(`^${label}`) });
      expect(option.querySelector(".palette-alias")).toHaveTextContent(word);
    }
    // The segment alone finds a page whose aliases do not say it.
    await userEvent.clear(input);
    await userEvent.type(input, "welcome");
    const started = await screen.findByRole("option", { name: /^Getting started/ });
    expect(started).toBeVisible();
    expect(started.querySelector(".palette-alias")).toHaveTextContent("welcome");
  });

  it("finds records once the typing settles and opens a target as an Activity filter", async () => {
    const { router, calls } = mount();
    const input = await screen.findByPlaceholderText("Search");
    expect(screen.getByText("Type EB-1042, a case ID, a hostname, a provider id, an agent's name or number, or User 3.")).toBeInTheDocument();
    await userEvent.type(input, "ws01");
    const record = await screen.findByRole("option", { name: /^ws01\.example/ });
    expect(record).toHaveTextContent("device-01; endpoint, workstation, production");
    expect(calls.filter((call) => call.path === SEARCH)).toHaveLength(1);
    expect(called(calls, "GET", SEARCH, "?q=ws01")).toBe(true);
    expect(screen.getByRole("option", { name: "Activity where the target is ws01.example" })).toBeInTheDocument();
    await userEvent.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(router.state.location.search).toEqual({ target: TARGET.id });
  });

  it("opens an execution or an approval in the drawer, with its state as a badge", async () => {
    const { router } = mount();
    const input = await screen.findByPlaceholderText("Search");
    await userEvent.type(input, "7c21");
    const record = await screen.findByRole("option", { name: /Isolate endpoint on dc01/ });
    expect(within(record).getByText("Denied")).toBeInTheDocument();
    await userEvent.keyboard("{Enter}");
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ open: EXECUTION.id });
    });
    expect(destination(APPROVAL)).toEqual({ open: APPROVAL.execution_id });
    expect(destination(AGENT)).toEqual({ agent: AGENT.id });
    expect(goTo(AGENT)).toBe("Activity where the agent is Triage agent A");
    expect(goTo(EXECUTION)).toBeUndefined();
  });

  it("opens a person on their own page, built from the id, and renders a label as text (#678)", async () => {
    const { router } = mount();
    const input = await screen.findByPlaceholderText("Search");
    await userEvent.type(input, "user");
    expect(await screen.findByRole("option", { name: "Open User 3" })).toBeInTheDocument();
    expect(screen.getByText("<img src=x onerror=alert(1)> user")).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    await userEvent.click(screen.getByRole("option", { name: /^User 3/ }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/people/${PERSON.id}`);
    });
    expect(goTo(PERSON)).toBe("Open User 3");
  });

  it("offers no Ask where the deployment has no assistant", async () => {
    mount();
    await screen.findByPlaceholderText("Search");
    expect(screen.queryByText("Ask the assistant")).toBeNull();
  });

  it("carries the typed words to the Ask page rather than asking anything itself", async () => {
    const onClose = vi.fn();
    const { router } = mount(onClose, true);
    const input = await screen.findByPlaceholderText("Search or ask");
    expect(await screen.findByText("Ask the assistant")).toBeVisible();
    await userEvent.type(input, "why was device-01 denied");
    const ask = await screen.findByText("Ask: why was device-01 denied");
    await userEvent.click(ask);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/ask");
    });
    // The words travel in the address; nothing was sent to a model from the palette.
    expect(router.state.location.search).toEqual({ q: "why was device-01 denied" });
    expect(onClose).toHaveBeenCalled();
  });
});

describe("an edition's links in the palette (#496)", () => {
  // A server page an edition offers, as the hosted edition offers its signup page; core itself
  // offers none (`paletteLinks` is empty in core's edition).
  const LINK: EditionLink = {
    label: "Edition page",
    href: "/edition-page",
    icon: "plus",
    feature: "edition_feature",
    aliases: ["Other name"],
  };
  const edition: Edition = { ...core, paletteLinks: [LINK] };
  const admin = (features: readonly string[]): SessionSummary => ({ ...PLACEHOLDER, role: "ADMIN", features });

  it("offers none in core's edition, whatever features the session reports", async () => {
    mount(undefined, false, admin(["edition_feature"]));
    await screen.findByRole("group", { name: "Go to" });
    expect(screen.queryByRole("group", { name: "Actions" })).toBeNull();
  });

  it("offers a link only where the session's feature holds", async () => {
    mount(undefined, false, admin(["another_feature"]), edition);
    const pages = await screen.findByRole("group", { name: "Go to" });
    expect(within(pages).getByRole("option", { name: "Home" })).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Actions" })).toBeNull();
    expect(screen.queryByRole("option", { name: "Edition page" })).toBeNull();
  });

  it("lists it in its own group before the pages, matched by name, and leaves the console for it", async () => {
    // jsdom cannot leave the page; the palette only asks the browser to.
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });
    const onClose = vi.fn();
    const { router } = mount(onClose, false, admin(["edition_feature"]), edition);
    const input = await screen.findByPlaceholderText("Search");
    const actions = await screen.findByRole("group", { name: "Actions" });
    expect(within(actions).getAllByRole("option").map((option) => option.textContent)).toEqual(["Edition page"]);
    // The first entry a keyboard lands on after the disabled records hint, above every page.
    const selectable = screen
      .getAllByRole("option")
      .filter((option) => option.getAttribute("aria-disabled") !== "true");
    expect(selectable[0]).toHaveAccessibleName("Edition page");
    await userEvent.type(input, "activ");
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: "Actions" })).toBeNull();
    });
    // Found by another name it goes by, as a page is by its aliases.
    await userEvent.clear(input);
    await userEvent.type(input, "other");
    await userEvent.click(await screen.findByRole("option", { name: "Edition page" }));
    // The browser leaves for the server page; the console's router goes nowhere.
    expect(assign).toHaveBeenCalledWith("/edition-page");
    expect(onClose).toHaveBeenCalled();
    expect(router.state.location.pathname).toBe("/");
  });
});

describe("the palette's Spaces group", () => {
  it("is absent for a reader with one space", async () => {
    const { calls } = mount();
    await screen.findByPlaceholderText("Search");
    // The Go to group still carries the Spaces **page**; what is absent is a space to switch
    // to, and the list is never asked for.
    expect(screen.queryByRole("option", { name: "Northwind" })).toBeNull();
    expect(called(calls, "GET", SPACES)).toBe(false);
  });

  it("lists the person's spaces and switches the session", async () => {
    const onClose = vi.fn();
    const { calls } = mount(onClose, false, MANY);
    await screen.findByPlaceholderText("Search");
    expect(await screen.findByRole("option", { name: "Southbank" })).toBeVisible();
    // The current one is named and cannot be chosen again.
    expect(await screen.findByRole("option", { name: "Northwind (current)" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    await userEvent.click(await screen.findByRole("option", { name: "Southbank" }));
    await waitFor(() => {
      expect(called(calls, "POST", SESSION_SPACE)).toBe(true);
    });
    expect(calls.find((call) => call.path === SESSION_SPACE)?.body).toEqual({ space_id: SOUTH });
    expect(onClose).toHaveBeenCalled();
  });

  it("names a record's space, so two customers' WS-001 are told apart", async () => {
    mount(undefined, false, MANY);
    const input = await screen.findByPlaceholderText("Search");
    await userEvent.type(input, "ws01");
    const record = await screen.findByRole("option", { name: /^ws01\.example/ });
    expect(record).toHaveTextContent("Northwind · device-01; endpoint, workstation, production");
  });
});

describe("the palette for a person with several workspaces (#678)", () => {
  const WORKSPACES = "/api/console/v1/session/workspaces";
  const item = (id: string, name: string, current: boolean) => ({
    tenant_id: id, name, current, kind: "ADMIN", roles: ["administrator"], entry: "open",
    waiting_state: current ? "current" : "counted", waiting: current ? null : 0, next_lapse: null, last_entered_at: null,
  });
  const ONE = [item("aaaaaaaa-0000-4000-8000-00000000000a", "Acme SOC", true)];
  const TWO = [...ONE, item("bbbbbbbb-0000-4000-8000-00000000000b", "Contoso", false)];

  function show(workspaces: unknown[]) {
    serve({ [SEARCH]: answers, [SPACES]: SPACE_PAGE, [SESSION_SPACE]: {}, [WORKSPACES]: { workspaces } });
    const rootRoute = createRootRoute({ component: () => <CommandPalette open onClose={() => undefined} /> });
    const home = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => null });
    const router = createRouter({ routeTree: rootRoute.addChildren([home]), history: createMemoryHistory({ initialEntries: ["/"] }) });
    render(
      <SessionContext.Provider value={{ ...PLACEHOLDER, role: "ADMIN", canSwitchWorkspaces: true, tenant: { id: "aaaaaaaa-0000-4000-8000-00000000000a", name: "Acme SOC", detail: "" } }}>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </SessionContext.Provider>,
    );
  }

  it("heads the records Records for one workspace", async () => {
    show(ONE);
    expect(await screen.findByRole("group", { name: "Records" })).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Workspaces" })).toBeNull();
  });

  it("names the workspace over the records, and offers the other workspace, for two", async () => {
    show(TWO);
    expect(await screen.findByRole("group", { name: "Records in Acme SOC" })).toBeInTheDocument();
    const group = await screen.findByRole("group", { name: "Workspaces" });
    expect(within(group).getByRole("option", { name: "Switch to Contoso" })).toBeInTheDocument();
  });
});
