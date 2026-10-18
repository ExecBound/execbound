// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, useRouter, type AnyRouter } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PageHeading } from "../components/ui/PageHeading";
import { NotFound } from "../components/NotFound";
import { aliasesOf } from "../components/ui/aliases";
import { holdFocus, moveFocusNext } from "../lib/focus";
import { setSingleKeys } from "../lib/keys";
import { usePageName, type PageName } from "./page-name";
import { EditionContext, type Edition } from "../edition/context";
import { edition as core } from "../edition/core";
import { NO_SERVICE, PLACEHOLDER, SessionContext, type SessionStop, type SessionSummary } from "../lib/session";
import { answerWith } from "../test/page";
import { entryFor, FOOTER, NAVIGATION, phoneTabs, visible, type NavigationEntry } from "./navigation";
import { Shell } from "./Shell";

function harness(session: SessionSummary, initial = "/", edition: Edition = core) {
  // The shell reads the navigation counts through the Query client; a test gives it one that
  // never retries, and the page it would ask is not there, so the pills stay empty.
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <QueryClientProvider client={queryClient}>
        <EditionContext.Provider value={edition}>
          <SessionContext.Provider value={session}>
            <Shell>
              <Outlet />
            </Shell>
          </SessionContext.Provider>
        </EditionContext.Provider>
      </QueryClientProvider>
    ),
  });
  const pages = [...NAVIGATION, ...edition.navigation, ...FOOTER].map((entry) =>
    createRoute({
      getParentRoute: () => rootRoute,
      path: entry.to,
      component: () => <PageHeading title={entry.label} />,
    }),
  );
  return createRouter({
    routeTree: rootRoute.addChildren(pages),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
}

// The palette reads the search endpoint, so the shell it lives in needs a query client, as
// the application's root gives it one.
function mount(router: AnyRouter): void {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

const approver: SessionSummary = {
  role: "APPROVER",
  mode: "ENFORCE",
  tenant: { name: "Acme SOC", detail: "Production" },
  space: null,
  spaces: 1,
  allSpaces: false,
  person: { label: "A. Rivera", detail: "Approver", initials: "AR" },
  stop: null,
  assistant: false,
  invitations: false, mail: true,
  features: [],
  csrf: "",
};

const admin: SessionSummary = {
  role: "ADMIN",
  mode: "ENFORCE",
  tenant: { name: "Acme SOC", detail: "" },
  space: null,
  spaces: 1,
  allSpaces: false,
  person: { label: "J. Okafor", detail: "Administrator", initials: "JO" },
  stop: null,
  assistant: false,
  invitations: false, mail: true,
  features: [],
  csrf: "",
};

const stopped: SessionStop = {
  at: "2026-09-19T06:10:00+00:00",
  by: "0a1b2c3d-0000-4000-8000-000000000009",
  reason: "Contain <b>agent 7</b>",
  byName: "User 1",
};

describe("the navigation list", () => {
  it("uses capabilities and keeps loading and viewer navigation closed to mutations", () => {
    expect(visible(NAVIGATION, "UNKNOWN", { permissions: ["access.manage"] })).toEqual([]);
    expect(visible(NAVIGATION, "VIEWER", { permissions: ["console.read"] }).map((entry) => entry.label)).toEqual(["Home", "Activity", "Live board"]);
    const policy = visible(NAVIGATION, "POLICY_MANAGER", { permissions: ["console.read", "policy.manage"] }).map((entry) => entry.label);
    expect(policy).toContain("Policies");
    expect(policy).not.toContain("Users");
    expect(policy).not.toContain("Approvals");
    expect(visible(NAVIGATION, "ADMIN", { permissions: ["console.read", "access.manage"] }).map((entry) => entry.label)).not.toContain("Approvals");
  });
  it("shows an approver Home, Approvals, Activity, Live board and Settings", () => {
    expect(visible(NAVIGATION, "APPROVER").map((entry) => entry.label)).toEqual([
      "Home",
      "Approvals",
      "Activity",
      "Live board",
    ]);
    expect(visible(FOOTER, "APPROVER").map((entry) => entry.label)).toEqual(["Help & support", "My account"]);
    expect(phoneTabs("APPROVER").map((entry) => entry.label)).toEqual(["Approvals", "Activity", "Live board", "My account"]);
    expect(phoneTabs("ADMIN")[0]?.label).toBe("Home");
    // An entry that names a feature is hidden unless the caller says the deployment has it,
    // so a console built for a deployment with no assistant offers no door to one (#330).
    expect(visible(NAVIGATION, "UNKNOWN").map((entry) => entry.label)).not.toContain("Ask");
    expect(visible(NAVIGATION, "UNKNOWN", { assistant: true, invitations: true })).toHaveLength(0);
    expect(visible(NAVIGATION, "APPROVER", { assistant: true }).map((entry) => entry.label)).toContain("Ask");
    // The slot pool's Invitations entry is the hosted edition's (#496): core's list has
    // none, with the feature or without it.
    expect(visible(NAVIGATION, "ADMIN", { invitations: true }).map((entry) => entry.label)).not.toContain("Invitations");
    expect(phoneTabs("ADMIN", { invitations: true }).map((entry) => entry.label)).toEqual([
      "Home",
      "Approvals",
      "Activity",
      "Live board",
      "My account",
    ]);
  });

  it("names the entry a path belongs to, among the entries this person can see", () => {
    expect(entryFor("/", [], "APPROVER", {})?.label).toBe("Home");
    expect(entryFor("/approvals/abc", [], "APPROVER", {})?.label).toBe("Approvals");
    expect(entryFor("/nowhere", [], "ADMIN", {})).toBeUndefined();
    // A page the deployment does not have, or this role cannot open, is named by nothing.
    expect(entryFor("/ask", [], "ADMIN", {})).toBeUndefined();
    expect(entryFor("/ask", [], "ADMIN", { assistant: true })?.label).toBe("Ask");
    expect(entryFor("/people", [], "APPROVER", {})).toBeUndefined();
  });

  it("gives every page the words people search for it by (NV10, #678)", () => {
    const aliases = Object.fromEntries(
      [...NAVIGATION, ...FOOTER].map((entry) => [entry.label, aliasesOf(entry)]),
    );
    expect(aliases).toEqual({
      Home: [],
      Approvals: ["Reviews", "Decisions", "Queue"],
      Activity: ["Requests", "History", "Audit"],
      Ask: [],
      "Live board": ["Board", "Live"],
      Policies: ["Bundles", "Policy versions", "Rules"],
      "Agent connections": ["Agents"],
      Users: ["People", "Members", "Teammates"],
      "Groups & roles": ["Groups", "Roles", "Permissions"],
      "API keys": ["API tokens", "Bearer tokens", "Access keys", "Agent credentials"],
      "Approval rules": ["Approvers", "Reviewers", "Approver scopes"],
      Spaces: ["Space"],
      Monitoring: ["Findings", "Sources", "Tines"],
      "Getting started": ["Setup", "Onboarding"],
      "Workspace settings": ["Tenant", "Organisation", "Organization", "Mode", "Emergency stop"],
      "Help & support": ["Support", "Documentation", "Keyboard"],
      "My account": ["Settings", "Profile", "Password", "MFA"],
    });
  });

  it("gives every page its own icon", () => {
    const icons = [...NAVIGATION, ...FOOTER].map((entry) => entry.icon);
    expect(new Set(icons).size).toBe(icons.length);
  });

  it("gives the pages their g keys, each once (NV5, #678)", () => {
    const keys = [...NAVIGATION, ...FOOTER].flatMap((entry) => (entry.key === undefined ? [] : [[entry.key, entry.label]]));
    expect(Object.fromEntries(keys)).toEqual({
      h: "Home",
      a: "Approvals",
      c: "Activity",
      l: "Live board",
      p: "Policies",
      n: "Agent connections",
      u: "Users",
      m: "Monitoring",
      s: "Workspace settings",
      "?": "Help & support",
    });
    expect(new Set(keys.map(([key]) => key)).size).toBe(keys.length);
  });
});

describe("the shell", () => {
  it("renders the sidebar, the breadcrumb, the mode and the skip link", async () => {
    mount(harness(approver));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(crumbs).toHaveTextContent("Acme SOC");
    expect(within(crumbs).getByText("Home")).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("Enforcing")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Emergency stop/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Policy/ })).toBeNull();
  });

  it("moves focus to the heading after a navigation", async () => {
    mount(harness(admin));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const sidebar = screen.getByRole("navigation", { name: "Main" });
    await userEvent.click(within(sidebar).getByRole("link", { name: "Activity" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: "Activity" })).toHaveFocus();
    });
  });

  it("collapses to a rail and remembers it, and opens the palette on Ctrl K", async () => {
    window.localStorage.clear();
    mount(harness(PLACEHOLDER));
    await screen.findByRole("heading", { level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Collapse the sidebar" }));
    expect(screen.getByRole("button", { name: "Expand the sidebar" })).toHaveAttribute("aria-pressed", "true");
    expect(window.localStorage.getItem("eb.sidebar")).toBe("rail");
    await userEvent.keyboard("{Control>}k{/Control}");
    expect(await screen.findByRole("dialog", { name: "Search" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
  });

  it("opens nothing on ? while single keys are off, and still opens search on Ctrl K (NV6, #678)", async () => {
    setSingleKeys(false);
    try {
      mount(harness(admin));
      await screen.findByRole("heading", { level: 1, name: "Home" });
      // The handler loads with the after-paint layer, which the palette opening shows is there.
      await userEvent.keyboard("{Control>}k{/Control}");
      await screen.findByRole("dialog", { name: "Search" });
      await userEvent.keyboard("{Escape}");
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      });
      await userEvent.keyboard("?");
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(screen.queryByRole("dialog", { name: "Keyboard" })).toBeNull();
    } finally {
      setSingleKeys(true);
    }
  });

  it("goes to a page on g then its letter (NV5, #678)", async () => {
    mount(harness(admin));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await userEvent.keyboard("{Control>}k{/Control}");
    await screen.findByRole("dialog", { name: "Search" });
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await userEvent.keyboard("ga");
    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: "Approvals" })).toHaveFocus();
    });
  });

  it("links the footer to the deployment's own pages, and to none it does not name (#496)", async () => {
    const service = {
      ...NO_SERVICE,
      privacy_url: "https://example.com/privacy",
      terms_url: "https://example.com/terms",
      status_url: "https://example.com/status",
      source_url: "https://example.com/source",
    };
    mount(harness({ ...admin, service }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const footer = within(await screen.findByRole("contentinfo", { name: "Service information" }));
    expect(footer.getAllByRole("link").map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["Help", "/help"],
      ["Privacy", "https://example.com/privacy"],
      ["Terms", "https://example.com/terms"],
      ["Status", "https://example.com/status"],
      ["Source", "https://example.com/source"],
    ]);
  });

  it("links the public source where the deployment names nothing else (#496)", async () => {
    const service = { ...NO_SERVICE, source_url: "https://github.com/ExecBound/execbound" };
    mount(harness({ ...admin, service }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const footer = await screen.findByRole("contentinfo", { name: "Service information" });
    expect(within(footer).getAllByRole("link").map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["Help", "/help"],
      ["Source", "https://github.com/ExecBound/execbound"],
    ]);
    expect(footer.textContent).toMatch(/^Powered by ExecBound · Help · Source$/);
  });

  it("keeps only its own Help in the footer where the deployment names no page (#496)", async () => {
    mount(harness(admin));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const footer = await screen.findByRole("contentinfo", { name: "Service information" });
    expect(within(footer).getAllByRole("link").map((link) => link.getAttribute("href"))).toEqual(["/help"]);
    expect(footer.textContent).toMatch(/^Powered by ExecBound · Help$/);
  });

  it("credits the deployment's operator where it names one, and the software where it names none", async () => {
    mount(harness({ ...admin, service: { ...NO_SERVICE, operator: "Example Operations Ltd" } }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const footer = await screen.findByRole("contentinfo", { name: "Service information" });
    expect(footer.textContent).toBe(`© ${String(new Date().getFullYear())} Example Operations Ltd · Help`);
    expect(footer.textContent).not.toContain("Powered by");
  });
});

/** A shell with one extra page whose buttons change only the query, as a filter chip does. */
function filterHarness(session: SessionSummary) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <QueryClientProvider client={queryClient}>
        <SessionContext.Provider value={session}>
          <Shell>
            <Outlet />
          </Shell>
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  function Filters() {
    // The harness's own route is not in the application's route types, so it goes by history.
    const { history } = useRouter();
    return (
      <>
        <PageHeading title="Filters" />
        {["a", "b"].map((state) => (
          <button
            key={state}
            type="button"
            onClick={() => {
              history.push(`/filters?state=${state}`);
            }}
          >
            State {state}
          </button>
        ))}
      </>
    );
  }
  const pages = [
    createRoute({ getParentRoute: () => rootRoute, path: "/filters", component: Filters }),
    ...[...NAVIGATION, ...FOOTER].map((entry) =>
      createRoute({ getParentRoute: () => rootRoute, path: entry.to, component: () => <PageHeading title={entry.label} /> }),
    ),
  ];
  return createRouter({
    routeTree: rootRoute.addChildren(pages),
    history: createMemoryHistory({ initialEntries: ["/filters"] }),
  });
}

const frame = () => new Promise((resolve) => requestAnimationFrame(resolve));

describe("focus on a change of the query alone (NV14, #678)", () => {
  it("stays on the control that changed the query", async () => {
    const router = filterHarness(admin);
    mount(router);
    await screen.findByRole("heading", { level: 1, name: "Filters" });
    await userEvent.click(screen.getByRole("button", { name: "State a" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "a" });
    });
    await frame();
    await frame();
    expect(screen.getByRole("button", { name: "State a" })).toHaveFocus();
  });

  it("moves to the heading on a query change after moveFocusNext", async () => {
    const router = filterHarness(admin);
    mount(router);
    await screen.findByRole("heading", { level: 1, name: "Filters" });
    moveFocusNext();
    await userEvent.click(screen.getByRole("button", { name: "State b" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: "Filters" })).toHaveFocus();
    });
  });

  it("spends a hold on the next navigation, so a later change of page still moves the focus", async () => {
    const router = filterHarness(admin);
    mount(router);
    await screen.findByRole("heading", { level: 1, name: "Filters" });
    holdFocus();
    await userEvent.click(screen.getByRole("button", { name: "State a" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "a" });
    });
    await frame();
    const sidebar = screen.getByRole("navigation", { name: "Main" });
    await userEvent.click(within(sidebar).getByRole("link", { name: "Activity" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { level: 1, name: "Activity" })).toHaveFocus();
    });
  });
});

/** A shell over one page that declares the given name, beside the navigation's own pages. */
function namedHarness(session: SessionSummary, name: PageName, initial = "/policy/named") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <QueryClientProvider client={queryClient}>
        <SessionContext.Provider value={session}>
          <Shell>
            <Outlet />
          </Shell>
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  function Named() {
    usePageName(name);
    return <PageHeading title="Named" />;
  }
  const pages = [
    createRoute({ getParentRoute: () => rootRoute, path: "/policy/named", component: Named }),
    ...[...NAVIGATION, ...FOOTER].map((entry) =>
      createRoute({ getParentRoute: () => rootRoute, path: entry.to, component: () => <PageHeading title={entry.label} /> }),
    ),
  ];
  return createRouter({
    routeTree: rootRoute.addChildren(pages),
    history: createMemoryHistory({ initialEntries: [initial] }),
    defaultNotFoundComponent: NotFound,
  });
}

const RULES_NAME: PageName = {
  crumbs: [
    { label: "Policies", link: { to: "/policy" } },
    { label: "Policy version acddee11", link: { to: "/policy" } },
  ],
  current: "Rules",
  title: [],
};

describe("the breadcrumb (NV9, #678)", () => {
  it("links each ancestor a page names and marks the page itself current", async () => {
    mount(namedHarness(admin, RULES_NAME));
    await screen.findByRole("heading", { level: 1, name: "Named" });
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    await waitFor(() => {
      expect(within(crumbs).getByText("Rules")).toHaveAttribute("aria-current", "page");
    });
    const links = within(crumbs).getAllByRole("link", { hidden: true }).filter((link) => link.classList.contains("crumb-link"));
    expect(links.map((link) => [link.textContent, link.getAttribute("href")])).toEqual([
      ["Policies", "/policy"],
      ["Policy version acddee11", "/policy"],
    ]);
    // Only the page itself is current; an ancestor the address starts with is not.
    expect(links.map((link) => link.getAttribute("aria-current"))).toEqual([null, null]);
  });

  it("names a missing page Not found", async () => {
    mount(namedHarness(admin, RULES_NAME, "/nowhere"));
    await screen.findByRole("heading", { level: 1, name: "There is no page here" });
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    await waitFor(() => {
      expect(within(crumbs).getByText("Not found")).toHaveAttribute("aria-current", "page");
    });
  });

  it("puts the earlier ancestors behind one disclosure that opens them as links and closes on Escape", async () => {
    mount(namedHarness(admin, RULES_NAME));
    const more = await screen.findByRole("button", { name: "Show 1 more level" });
    expect(more).toHaveAttribute("aria-expanded", "false");
    const list = document.getElementById(more.getAttribute("aria-controls") ?? "");
    expect(list).not.toBeNull();
    expect(list).not.toBeVisible();
    await userEvent.click(more);
    expect(more).toHaveAttribute("aria-expanded", "true");
    expect(list).toBeVisible();
    if (list === null) throw new Error("No list");
    expect(within(list).getByRole("link", { name: "Policies" })).toHaveAttribute("href", "/policy");
    within(list).getByRole("link", { name: "Policies" }).focus();
    await userEvent.keyboard("{Escape}");
    expect(more).toHaveAttribute("aria-expanded", "false");
    expect(more).toHaveFocus();
    // The ancestor it stands in for is marked to be hidden only while it stands in.
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    const middle = within(crumbs).getAllByRole("listitem").filter((item) => item.classList.contains("crumb-middle"));
    expect(middle.map((item) => item.textContent)).toEqual(["Policies"]);
  });

  it("has no disclosure for a single ancestor", async () => {
    mount(namedHarness(admin, { crumbs: [{ label: "Approvals", link: { to: "/approvals" } }], current: "EB-7", title: [] }));
    await screen.findByRole("heading", { level: 1, name: "Named" });
    expect(screen.queryByRole("button", { name: /more level/ })).toBeNull();
  });
});

describe("the Monitoring entry (MQ3, #678)", () => {
  function tenant(monitoring: { open_findings: number; stale: number; overdue: number }) {
    return { body: { monitoring: { sources: 1, reporting: 0, ...monitoring } } };
  }

  async function monitoringLink() {
    const nav = await screen.findByRole("navigation", { name: "Main" });
    return within(nav).getByRole("link", { name: /^Monitoring/ });
  }

  it("lands on the open findings it counts, and says what it counts", async () => {
    answerWith({ "GET /api/console/v1/tenant": tenant({ open_findings: 3, stale: 1, overdue: 1 }) });
    mount(harness(admin));
    const link = await monitoringLink();
    await waitFor(() => {
      expect(link).toHaveAttribute("href", "/monitor?view=findings");
    });
    expect(within(link).getByLabelText("3 open findings; 2 sources or collections quiet")).toHaveTextContent("3");
  });

  it("lands on what is quiet when nothing is open, and on Monitoring when nothing waits", async () => {
    answerWith({ "GET /api/console/v1/tenant": tenant({ open_findings: 0, stale: 1, overdue: 1 }) });
    mount(harness(admin));
    const link = await monitoringLink();
    await waitFor(() => {
      expect(link).toHaveAttribute("href", "/monitor?focus=quiet");
    });
    expect(within(link).getByLabelText("2 monitoring sources or collections quiet")).toHaveTextContent("2");
  });

  it("shows no pill and a bare link when nothing waits", async () => {
    const seen = answerWith({ "GET /api/console/v1/tenant": tenant({ open_findings: 0, stale: 0, overdue: 0 }) });
    mount(harness(admin));
    const link = await monitoringLink();
    await waitFor(() => {
      expect(seen.map((request) => request.path)).toContain("/api/console/v1/tenant");
    });
    expect(link).toHaveAttribute("href", "/monitor");
    expect(link.querySelector(".pill")).toBeNull();
  });

  it("stays current on every Monitoring view", async () => {
    answerWith({ "GET /api/console/v1/tenant": tenant({ open_findings: 3, stale: 0, overdue: 0 }) });
    mount(harness(admin, "/monitor?view=agents"));
    const link = await monitoringLink();
    await waitFor(() => {
      expect(link).toHaveAttribute("href", "/monitor?view=findings");
    });
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("is not offered to an approver, and nothing reads the tenant for one", async () => {
    const seen = answerWith({});
    mount(harness(approver));
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await waitFor(() => {
      expect(seen.map((request) => request.path)).toContain("/api/console/v1/approvals");
    });
    expect(within(nav).queryByRole("link", { name: /^Monitoring/ })).toBeNull();
    expect(seen.map((request) => request.path)).not.toContain("/api/console/v1/tenant");
  });
});

describe("the emergency stop in the shell", () => {
  it("opens the stop dialog for an administrator, and shows no banner without a stop", async () => {
    render(<RouterProvider router={harness(admin)} />);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    expect(screen.queryByText(/Emergency stop active/)).toBeNull();
    expect(screen.queryByText("Stop active")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Emergency stop" }));
    expect(await screen.findByRole("dialog", { name: "Activate the emergency stop?" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
  });

  it("shows the banner with the reason as text and Resume to an administrator", async () => {
    render(<RouterProvider router={harness({ ...admin, stop: stopped })} />);
    const banner = (await screen.findByText(/Emergency stop active/)).closest(".banner");
    expect(banner).toHaveTextContent("Contain <b>agent 7</b>");
    expect(banner).toHaveTextContent("activated by User 1 at 2026-09-19 06:10 UTC");
    expect(banner).toHaveTextContent("until an administrator resumes this workspace.");
    expect(banner).not.toHaveTextContent("0a1b2c3d");
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByRole("button", { name: "Emergency stop" })).toHaveClass("btn-danger");
    await userEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(await screen.findByRole("dialog", { name: "Resume this tenant?" })).toBeInTheDocument();
  });

  it("shows an approver the state, the banner, and no button", async () => {
    render(<RouterProvider router={harness({ ...approver, stop: { ...stopped, byName: null } })} />);
    expect(await screen.findByText("Stop active")).toBeInTheDocument();
    expect(screen.getByText(/Emergency stop active/)).toBeInTheDocument();
    // An approver's session is not told which administrator stopped the workspace (#678).
    expect(screen.getByText(/Emergency stop active/).closest(".banner")).toHaveTextContent("activated by an administrator at");
    expect(screen.queryByRole("button", { name: "Emergency stop" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume" })).toBeNull();
  });
});

describe("the edition in the shell (#496)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const extra: NavigationEntry = {
    label: "Edition page",
    to: "/edition-page",
    icon: "invite",
    group: "Team & access",
    roles: ["ADMIN"],
    phone: true,
    tabLabel: "Edition",
  };
  const sidebarOnly: NavigationEntry = {
    label: "Edition report",
    to: "/edition-report",
    icon: "activity",
    group: "Visibility",
    roles: ["ADMIN"],
  };

  it("lists an edition's entry after core's in the sidebar, the tab bar, the breadcrumbs and the palette", async () => {
    mount(harness(admin, "/edition-page", { ...core, navigation: [extra] }));
    await screen.findByRole("heading", { level: 1, name: "Edition page" });
    const team = within(screen.getByRole("navigation", { name: "Main" })).getByRole("list", { name: "Team & access" });
    expect(within(team).getAllByRole("link").at(-1)).toHaveTextContent("Edition page");
    const tabs = screen.getByRole("navigation", { name: "Main, phone" });
    expect(within(tabs).getByRole("link", { name: "Edition" })).toHaveAttribute("href", "/edition-page");
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByText("Edition page")).toHaveAttribute("aria-current", "page");
    await userEvent.keyboard("{Control>}k{/Control}");
    const palette = await screen.findByRole("dialog", { name: "Search" });
    expect(within(palette).getByText("Edition page")).toBeInTheDocument();
  });

  it("puts an edition's entry in the phone's tab bar only where the entry asks", async () => {
    mount(harness(admin, "/", { ...core, navigation: [extra, sidebarOnly] }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const sidebar = screen.getByRole("navigation", { name: "Main" });
    expect(within(sidebar).getByRole("link", { name: "Edition report" })).toHaveAttribute("href", "/edition-report");
    const tabs = screen.getByRole("navigation", { name: "Main, phone" });
    expect(within(tabs).getAllByRole("link").map((link) => link.textContent)).toEqual([
      "Home",
      "Approvals",
      "Activity",
      "Live",
      "Edition",
      "My account",
    ]);
  });

  it("tells the edition the console opened", async () => {
    const event = vi.fn();
    mount(harness(admin, "/", { ...core, event }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    expect(event).toHaveBeenCalledWith("account_opened");
  });

  it("asks nothing for a count in core", async () => {
    const seen = answerWith({});
    mount(harness(admin));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    // The shell's own reads have gone out, and a count asked for on opening would have gone with them.
    await waitFor(() => {
      expect(seen.map((request) => request.path)).toContain("/api/console/v1/approvals");
    });
    expect(seen.map((request) => request.path)).not.toContain("/api/console/v1/account/preferences");
  });

  it("puts the edition's top bar items among the actions", async () => {
    mount(harness(admin, "/", { ...core, TopBarItems: () => <a href="/edition-action">Edition action</a> }));
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const link = screen.getByRole("link", { name: "Edition action" });
    expect(link.closest(".topbar-actions")).not.toBeNull();
  });
});

describe("the sidebar's fold (UX11, #678)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("scrolls only the main navigation and keeps the footer, the account and Sign out outside it", async () => {
    answerWith({});
    mount(harness({ ...admin, csrf: "token" }));
    const sidebar = await screen.findByRole("navigation", { name: "Main" });
    const scroll = sidebar.querySelector(".sidebar-scroll");
    const foot = sidebar.querySelector(".sidebar-foot");
    expect(scroll).not.toBeNull();
    expect(foot).not.toBeNull();
    expect(within(scroll as HTMLElement).getByRole("link", { name: "Home" })).toBeInTheDocument();
    const signOut = within(sidebar).getByRole("button", { name: /Sign out/ });
    expect(foot?.contains(signOut)).toBe(true);
    expect(scroll?.contains(signOut)).toBe(false);
    expect(foot?.querySelector(".account")).not.toBeNull();
    expect(within(foot as HTMLElement).getByRole("link", { name: "My account" })).toBeInTheDocument();
    // With no setup read, Getting started is an ordinary footer row.
    expect(within(foot as HTMLElement).getByRole("link", { name: "Getting started" })).toBeInTheDocument();
  });
});
