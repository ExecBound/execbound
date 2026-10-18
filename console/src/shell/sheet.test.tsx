// SPDX-License-Identifier: AGPL-3.0-only
// The phone's navigation sheet (NV8, #678): Menu opens the grouped list the sidebar shows, with
// its pills, and no text input takes the focus; choosing an entry closes the sheet and the page's
// heading takes the focus.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PageHeading } from "../components/ui/PageHeading";
import { EditionContext, type Edition } from "../edition/context";
import { edition as core } from "../edition/core";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";
import { answerWith } from "../test/page";
import { FOOTER, NAVIGATION } from "./navigation";
import { Shell } from "./Shell";

const admin: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  mode: "ENFORCE",
  tenant: { name: "Acme SOC", detail: "" },
  person: { label: "J. Okafor", detail: "Administrator", initials: "JO" },
  csrf: "token",
};

function mount(session: SessionSummary, edition: Edition = core) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <EditionContext.Provider value={edition}>
        <SessionContext.Provider value={session}>
          <Shell>
            <Outlet />
          </Shell>
        </SessionContext.Provider>
      </EditionContext.Provider>
    ),
  });
  const pages = [...NAVIGATION, ...FOOTER].map((entry) =>
    createRoute({ getParentRoute: () => rootRoute, path: entry.to, component: () => <PageHeading title={entry.label} /> }),
  );
  const router = createRouter({
    routeTree: rootRoute.addChildren(pages),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

async function openSheet(): Promise<HTMLElement> {
  await screen.findByRole("heading", { level: 1, name: "Home" });
  const menu = screen.getByRole("button", { name: "Navigation menu" });
  expect(menu).toHaveAttribute("aria-haspopup", "dialog");
  expect(menu).toHaveAttribute("aria-expanded", "false");
  await userEvent.click(menu);
  const sheet = await screen.findByRole("dialog", { name: "Menu" });
  expect(menu).toHaveAttribute("aria-expanded", "true");
  return sheet;
}

const names = (root: HTMLElement) =>
  within(root)
    .getAllByRole("link", { hidden: true })
    .map((link) => link.textContent);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("where the navigation sheet loads", () => {
  it("is reached only through the after-paint layer, never from a page's first load", () => {
    const sources = import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}"], {
      query: "?raw",
      import: "default",
      eager: true,
    });
    const importers = Object.entries(sources)
      .filter(([, text]) => /from "\.{1,2}\/(?:shell\/)?NavigationSheet"|import\("\.\/NavigationSheet"\)/.test(text))
      .map(([path]) => path);
    expect(importers).toEqual(["./AfterPaint.tsx"]);
    expect(sources["./Shell.tsx"]).toMatch(/lazy\(\(\) => import\("\.\/AfterPaint"\)\)/);
  });
});

describe("the navigation sheet (NV8, #678)", () => {
  it("opens with the Close button focused and no field focused", async () => {
    answerWith({});
    mount(admin);
    const sheet = await openSheet();
    await waitFor(() => {
      expect(within(sheet).getByRole("button", { name: "Close" })).toHaveFocus();
    });
    expect(sheet.querySelector("input:not([type=hidden]), textarea")).toBeNull();
  });

  it("lists every entry the sidebar lists, under the same headings, and the footer and Sign out", async () => {
    answerWith({});
    mount(admin);
    const sheet = await openSheet();
    const sidebar = screen.getByRole("navigation", { name: "Main", hidden: true });
    for (const group of ["Agent security", "Team & access", "Visibility"]) {
      const inSidebar = within(sidebar).getByRole("list", { name: group, hidden: true });
      const inSheet = within(sheet).getByRole("list", { name: group });
      expect(names(inSheet)).toEqual(names(inSidebar));
    }
    for (const label of ["Home", "Activity", "Getting started", "Workspace settings", "Help & support", "My account"]) {
      expect(within(sheet).getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(within(sheet).getByRole("button", { name: "Sign out" })).toBeInTheDocument();
    // The sidebar keeps its scrolling part and its pinned foot; the sheet scrolls as a whole and
    // lists Getting started as a plain entry.
    expect(sidebar.querySelector(".sidebar-scroll")).not.toBeNull();
    expect(sidebar.querySelector(".sidebar-foot")).not.toBeNull();
    expect(sheet.querySelector(".sidebar-scroll, .sidebar-foot, .started")).toBeNull();
  });

  it("shows the Monitoring pill the sidebar shows", async () => {
    answerWith({ "GET /api/console/v1/tenant": { body: { monitoring: { sources: 1, reporting: 0, open_findings: 3, stale: 0, overdue: 0 } } } });
    mount(admin);
    const sidebar = await screen.findByRole("navigation", { name: "Main" });
    await waitFor(() => {
      expect(within(sidebar).getByLabelText("3 open findings")).toBeInTheDocument();
    });
    const sheet = await openSheet();
    const pill = within(sheet).getByLabelText("3 open findings");
    expect(pill).toHaveTextContent("3");
    expect(within(sheet).getByRole("link", { name: /^Monitoring/ })).toHaveAttribute("href", "/monitor?view=findings");
  });

  it("closes on a choice and moves the focus to the page's heading", async () => {
    answerWith({});
    const router = mount(admin);
    const sheet = await openSheet();
    await userEvent.click(within(sheet).getByRole("link", { name: "Policies" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/policy");
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Menu" })).toBeNull();
    });
    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: "Policies" })).toHaveFocus();
    });
  });

  it("opens search from its Search row", async () => {
    answerWith({});
    mount(admin);
    const sheet = await openSheet();
    await userEvent.click(within(sheet).getByRole("button", { name: "Search" }));
    expect(await screen.findByRole("dialog", { name: /^Search/ })).toBeInTheDocument();
  });

  it("lists an edition's action where the feature holds, and Ask only with an assistant", async () => {
    answerWith({});
    const edition: Edition = {
      ...core,
      paletteLinks: [{ label: "Create a workspace", href: "/signup", icon: "plus", feature: "create_workspace" }],
    };
    mount({ ...admin, features: ["create_workspace"], assistant: true }, edition);
    const sheet = await openSheet();
    const actions = within(sheet).getByRole("list", { name: "Actions" });
    expect(within(actions).getByRole("link", { name: "Create a workspace" })).toHaveAttribute("href", "/signup");
    // Ask is listed once, among the pages, as the sidebar lists it.
    expect(within(sheet).getAllByRole("link", { name: "Ask" })).toHaveLength(1);
    expect(within(sheet).getByRole("link", { name: "Ask" })).toHaveAttribute("href", "/ask");
  });

  it("offers no Ask without an assistant", async () => {
    answerWith({});
    mount(admin);
    const sheet = await openSheet();
    expect(within(sheet).queryByRole("link", { name: "Ask" })).toBeNull();
  });
});
