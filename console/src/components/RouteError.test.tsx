// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { client } from "../api/client.gen";
import { forgetReports } from "../lib/client-errors";
import { NO_SERVICE, SessionContext, type SessionSummary } from "../lib/session";
import { Shell } from "../shell/Shell";
import { PageHeading } from "./ui/PageHeading";
import { RouteError } from "./RouteError";

const APPROVAL = "a0000000-0000-4000-8000-000000000002";
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

/** The real shell around two pages that throw while `broken` says so, as main.tsx wires it. */
function mount(initial: string, broken: { now: boolean; with?: unknown }, session: SessionSummary = admin) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rootRoute = createRootRoute({
    component: () => (
      <SessionContext.Provider value={session}>
        <Shell>
          <Outlet />
        </Shell>
      </SessionContext.Provider>
    ),
  });
  const page = (title: string) => () => {
    // A typed refusal is a plain object with a code, as the generated client throws one.
    // eslint-disable-next-line @typescript-eslint/only-throw-error
    if (broken.now) throw broken.with ?? new Error("a component failed while rendering");
    return <PageHeading title={title} />;
  };
  const approval = createRoute({ getParentRoute: () => rootRoute, path: "/approvals/$approvalId", component: page("Approval") });
  const activity = createRoute({ getParentRoute: () => rootRoute, path: "/activity", component: page("Activity") });
  const home = createRoute({ getParentRoute: () => rootRoute, path: "/", component: page("Home") });
  const router = createRouter({
    routeTree: rootRoute.addChildren([home, activity, approval]),
    history: createMemoryHistory({ initialEntries: [initial] }),
    defaultErrorComponent: RouteError,
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

let posted: Record<string, unknown>[] = [];

beforeEach(() => {
  // React reports a thrown render to the console before the boundary takes it.
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  forgetReports();
  posted = [];
  client.setConfig({ baseUrl: "http://console.test" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const path = new URL(input.url).pathname;
      if (path === "/api/console/v1/client-errors") posted.push((await input.json()) as Record<string, unknown>);
      return new Response(null, { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("a page that throws", () => {
  it("keeps the shell, says so in the page, offers the basic approval page and retries", async () => {
    const broken = { now: true };
    mount(`/approvals/${APPROVAL}`, broken);
    expect(await screen.findByRole("heading", { level: 1, name: "This page could not load" })).toBeInTheDocument();
    // The shell around the page is untouched: its navigation still goes somewhere.
    expect(screen.getAllByRole("link", { name: /Activity/ }).length).toBeGreaterThan(0);
    const classic = screen.getByRole("link", { name: "Use the basic approval page" });
    expect(classic).toHaveAttribute("href", `/approvals/${APPROVAL}/classic`);
    // Retry runs the route again; once the page renders, the boundary is gone.
    broken.now = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Approval" })).toBeInTheDocument();
    expect(screen.queryByText("This page could not load")).toBeNull();
  });

  it("offers no basic page away from an approval", async () => {
    mount("/activity", { now: true });
    expect(await screen.findByRole("heading", { level: 1, name: "This page could not load" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Use the basic approval page" })).toBeNull();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("what a failed page says and reports (NV16, #678)", () => {
  it("reports a failure once by its route's pattern, and shows the reference the report carries", async () => {
    mount(`/approvals/${APPROVAL}`, { now: true, with: new Error("secret 4111") });
    const reference = await screen.findByText(/^Reference/);
    await waitFor(() => {
      expect(posted).toHaveLength(1);
    });
    const report = posted[0] ?? {};
    expect(Object.keys(report).sort()).toEqual(["name", "release", "route", "stack_hash"]);
    expect(report.route).toBe("/approvals/$approvalId");
    expect(JSON.stringify(report)).not.toContain(APPROVAL);
    expect(JSON.stringify(report)).not.toContain("secret");
    expect(reference.textContent).toContain(String(report.stack_hash).slice(0, 8));
    expect(screen.queryByRole("link", { name: /email support/ })).toBeNull();
  });

  it("offers a mail to support with the reference where the deployment names an address", async () => {
    mount("/activity", { now: true }, { ...admin, service: { ...NO_SERVICE, support_email: "support@example.com" } });
    const link = await screen.findByRole("link", { name: "email support with this reference" });
    const reference = (await screen.findByText(/^Reference/)).querySelector(".mono")?.textContent ?? "";
    expect(link).toHaveAttribute("href", `mailto:support@example.com?subject=${encodeURIComponent(`ExecBound support: reference ${reference}`)}`);
  });

  it.each([
    ["FORBIDDEN", "You don't have access to this"],
    ["NOT_FOUND", "There is nothing here you can open"],
    ["UNAVAILABLE", "ExecBound is unavailable"],
  ])("says what a typed %s refusal means, and reports nothing", async (code, heading) => {
    mount("/activity", { now: true, with: { code, detail: "Refused." } });
    expect(await screen.findByRole("heading", { level: 1, name: heading })).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(posted).toHaveLength(0);
    expect(screen.queryByText(/^Reference/)).toBeNull();
    expect(document.body.textContent).not.toMatch(/no longer exists|record/);
  });

  it("shows the card without a reference, and sends nothing, where the browser cannot hash", async () => {
    vi.stubGlobal("crypto", {});
    mount("/activity", { now: true });
    expect(await screen.findByRole("heading", { level: 1, name: "This page could not load" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(posted).toHaveLength(0);
    expect(screen.queryByText(/^Reference/)).toBeNull();
    expect(screen.queryByRole("link", { name: /email support/ })).toBeNull();
  });
});
