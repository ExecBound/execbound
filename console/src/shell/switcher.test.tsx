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
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SessionView, SpacePage } from "../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../lib/session";
import { SessionContext } from "../lib/session";
import { Toaster } from "../components/ui/Toast";
import { called, json, serve } from "../test/api";
import { initialsOf, SpaceSwitcher } from "./SpaceSwitcher";

const SPACES = "/api/console/v1/spaces";
const SESSION_SPACE = "/api/console/v1/session/space";
const NORTH = "11111111-1111-4111-8111-111111111111";
const SOUTH = "22222222-2222-4222-8222-222222222222";
const OLD = "33333333-3333-4333-8333-333333333333";

function row(spaceId: string, name: string, detail: string | null, archivedAt: string | null = null) {
  return {
    space_id: spaceId,
    name,
    detail,
    created_at: "2026-09-01T00:00:00Z",
    archived_at: archivedAt,
    members: 2,
    agents: 3,
    pending: 1,
    findings: 0,
  };
}

function page(request: Request, administrator = true): Response {
  const url = new URL(request.url);
  const q = url.searchParams.get("q") ?? "";
  const state = url.searchParams.get("state") ?? "active";
  const all = [
    row(NORTH, "Northwind", "The first customer"),
    row(SOUTH, "Southbank <b>Ltd</b>", null),
    row(OLD, "Retired customer", null, "2026-09-10T00:00:00Z"),
  ];
  const items = all
    .filter((space) => (state === "active" ? space.archived_at === null : true))
    .filter((space) => space.name.toLowerCase().includes(q.toLowerCase()));
  const answer: SpacePage = {
    items,
    next_cursor: null,
    administrator,
    all_spaces: true,
    current_space_id: NORTH,
  };
  return json(answer);
}

/** The fresh session view the switch answers with; only what the shell reads is filled. */
function view(spaceId: string | null, name: string): SessionView {
  return {
    identity: { principal_id: "p", kind: "ADMIN", label: "J. Okafor", session_id: "s" },
    tenant: { tenant_id: "t", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
    space: spaceId === null ? null : { space_id: spaceId, name, archived: false },
    spaces: 3,
    all_spaces: true,
    stop: null,
    assistant: false,
    csrf: "token",
    csrf_token: "token",
    expires_at: "2026-09-21T00:00:00Z",
    release: null,
  } as unknown as SessionView;
}

const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  mode: "ENFORCE",
  tenant: { name: "Acme SOC", detail: "" },
  space: { id: NORTH, name: "Northwind", archived: false },
  spaces: 3,
  allSpaces: true,
  person: { label: "J. Okafor", detail: "Administrator", initials: "JO" },
};

function mount(
  session: SessionSummary = ADMIN,
  administrator = true,
  listed = (request: Request) => page(request, administrator),
) {
  const calls = serve({
    [SPACES]: listed,
    [SESSION_SPACE]: (_request: Request, body: unknown) => {
      const wanted = (body as { space_id: string | null }).space_id;
      return json(view(wanted, wanted === SOUTH ? "Southbank <b>Ltd</b>" : "Northwind"));
    },
  });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <>
        <SpaceSwitcher rail={false} />
        <Toaster />
        <Outlet />
      </>
    ),
  });
  const home = createRoute({ getParentRoute: () => rootRoute, path: "/", component: () => null });
  const spaces = createRoute({
    getParentRoute: () => rootRoute,
    path: "/spaces",
    validateSearch: (): Record<string, never> => ({}),
    component: () => null,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([home, spaces]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <SessionContext.Provider value={session}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </SessionContext.Provider>,
  );
  return { calls, queryClient, router };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the space switcher", () => {
  it("reads the space over the tenant and names both in its label", async () => {
    mount();
    const trigger = await screen.findByRole("button", {
      name: "Space Northwind in Acme SOC; change space",
    });
    expect(trigger).toHaveAttribute("aria-haspopup", "listbox");
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    // The tenant is the boundary and stays on screen under the space it divides.
    expect(within(trigger).getByText("Northwind")).toBeInTheDocument();
    expect(within(trigger).getByText("Acme SOC")).toBeInTheDocument();
  });

  it("lists the person's spaces with the current one marked, and All spaces", async () => {
    mount();
    await userEvent.click(await screen.findByRole("button", { name: /change space/ }));
    const list = await screen.findByRole("listbox", { name: "Spaces" });
    await waitFor(() => {
      expect(within(list).getByRole("option", { name: /Northwind/ })).toBeInTheDocument();
    });
    expect(within(list).getByRole("option", { name: /Northwind/ })).toHaveAttribute("aria-selected", "true");
    expect(within(list).getByRole("option", { name: /All spaces/ })).toHaveAttribute("aria-selected", "false");
    // An archived space is out of the list until it is asked for.
    expect(within(list).queryByRole("option", { name: /Retired customer/ })).toBeNull();
    await userEvent.click(screen.getByLabelText("Show archived"));
    await waitFor(() => {
      expect(within(list).getByRole("option", { name: /Retired customer/ })).toBeInTheDocument();
    });
  });

  it("keeps the spaces it read through a read that fails", async () => {
    let reads = 0;
    const { queryClient } = mount(ADMIN, true, (request: Request) =>
      ++reads === 1 ? page(request) : json({ code: "UNAVAILABLE", detail: "Unavailable." }, 503),
    );
    await userEvent.click(await screen.findByRole("button", { name: /change space/ }));
    const list = await screen.findByRole("listbox", { name: "Spaces" });
    await waitFor(() => {
      expect(within(list).getByRole("option", { name: /Southbank/ })).toBeInTheDocument();
    });
    await act(async () => {
      await queryClient.refetchQueries({ type: "active" });
    });
    expect(await screen.findByText("The spaces could not be read.")).toBeInTheDocument();
    expect(reads).toBe(2);
    expect(within(list).getByRole("option", { name: /Northwind/ })).toBeInTheDocument();
    expect(within(list).getByRole("option", { name: /Southbank/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /New space/ })).toBeInTheDocument();
  });

  it("switches the session, clears the cache and says where the person now is", async () => {
    const { calls, queryClient } = mount();
    queryClient.setQueryData(["probe"], "the old space's rows");
    await userEvent.click(await screen.findByRole("button", { name: /change space/ }));
    const option = await screen.findByRole("option", { name: /Southbank/ });
    await userEvent.click(option);
    await waitFor(() => {
      expect(called(calls, "POST", SESSION_SPACE)).toBe(true);
    });
    expect(calls.find((call) => call.path === SESSION_SPACE)?.body).toEqual({ space_id: SOUTH });
    // The whole cache goes, rather than an invalidate: the generated client's keys carry no
    // space, so a response already in flight would land under the new space's own key.
    await waitFor(() => {
      expect(queryClient.getQueryData(["probe"])).toBeUndefined();
    });
    expect(await screen.findByText("Now in Southbank <b>Ltd</b>.")).toBeInTheDocument();
    // The name is rendered as text, whatever a tenant called its space.
    expect(document.querySelector("b")).toBeNull();
  });

  it("closes on Escape and gives the trigger its focus back", async () => {
    mount();
    const trigger = await screen.findByRole("button", { name: /change space/ });
    await userEvent.click(trigger);
    expect(await screen.findByLabelText("Filter spaces")).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("listbox")).toBeNull();
    });
    expect(trigger).toHaveFocus();
  });

  it("filters on the server once the typing settles", async () => {
    const { calls } = mount();
    await userEvent.click(await screen.findByRole("button", { name: /change space/ }));
    await userEvent.type(await screen.findByLabelText("Filter spaces"), "south");
    await waitFor(() => {
      expect(called(calls, "GET", SPACES, "?state=active&q=south")).toBe(true);
    });
    expect(screen.queryByRole("option", { name: /Northwind/ })).toBeNull();
  });

  it("offers a tenant administrator New space and Manage spaces, as buttons", async () => {
    const { router } = mount();
    await userEvent.click(await screen.findByRole("button", { name: /change space/ }));
    expect(await screen.findByRole("button", { name: "New space" })).toBeInTheDocument();
    // Never a link: the browser suite asserts the main navigation's links are its entries.
    expect(screen.queryByRole("link", { name: "Manage spaces" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Manage spaces" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/spaces");
    });
  });

  it("offers a member no administration and no All spaces when they have one space", async () => {
    const member: SessionSummary = {
      ...ADMIN,
      role: "APPROVER",
      space: { id: NORTH, name: "Northwind", archived: false },
      spaces: 1,
      allSpaces: false,
    };
    mount(member, false);
    const trigger = await screen.findByRole("button", { name: "Space Northwind in Acme SOC" });
    expect(trigger).toHaveAttribute("aria-disabled", "true");
    expect(trigger).not.toHaveAttribute("aria-haspopup");
    await userEvent.click(trigger);
    expect(screen.queryByRole("listbox")).toBeNull();
  });
});

describe("the rail's initials", () => {
  it("takes the first letters of up to two words", () => {
    expect(initialsOf("Northwind")).toBe("N");
    expect(initialsOf("All spaces")).toBe("AS");
    expect(initialsOf("")).toBe("");
  });
});
