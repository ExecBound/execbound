// SPDX-License-Identifier: AGPL-3.0-only
// The bell (NV4, #678): a dot and a name that count what waits on this person, and a panel that
// says what is waiting and why it is theirs, every row a link, above the sign-in security log.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listApprovalsQueryKey, readOverviewQueryKey } from "../api/@tanstack/react-query.gen";
import type { OverviewView } from "../api/types.gen";
import { gateway, item, type Asked, type Reply } from "../approvals/fixtures";
import { PageHeading } from "../components/ui/PageHeading";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";
import { FOOTER, NAVIGATION } from "./navigation";
import { useCounts } from "./counts";
import Notifications from "./Notifications";
import { Shell } from "./Shell";

const NOW = Date.parse("2026-09-19T14:10:00Z");

const approver: SessionSummary = { ...PLACEHOLDER, role: "APPROVER", permissions: ["console.read", "approvals.decide"], csrf: "token" };
const admin: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"],
  csrf: "token",
};

const overview: OverviewView = {
  range: "7d",
  since: "2026-09-12T14:00:00Z",
  until: "2026-09-19T14:10:00Z",
  step_seconds: 21600,
  figures: { decisions: 0, executed: 0, denied: 0, held: 0, observed: 0, stale: 0, unknown: 0 },
  previous: { decisions: 0, executed: 0, denied: 0, held: 0, observed: 0, stale: 0, unknown: 0 },
  series: [],
  pending_approvals: 0,
  lapsed_approvals: 0,
  last_request_at: null,
  unsettled: 2,
  awaiting: [],
  monitoring: null,
  mode: "ENFORCE",
};

function queue(count: number, next: string | null = null, soonest = NOW + 192_000): Reply {
  return {
    body: {
      view: "pending",
      items: Array.from({ length: count }, (_, index) =>
        item({
          approval_id: `4b1e90c2-0000-4000-8000-${String(index).padStart(12, "0")}`,
          expires_at: new Date(soonest + index * 60_000).toISOString(),
        }),
      ),
      next_cursor: next,
      server_time: "2026-09-19T14:10:00Z",
    },
  };
}

const ACCOUNT: Reply = { body: { name: "Dana", requests: [], notifications: [{ sequence: 7, at: "2026-10-06T09:00:00Z", message: "A second factor was added." }] } };

function tenant(open: number): Reply {
  return { body: { monitoring: { sources: 1, reporting: 1, open_findings: open, stale: 0, overdue: 0 } } };
}

/** The shell's own counts, which keep the pending queue the panel observes. */
function ShellCounts() {
  useCounts();
  return null;
}

function panel(session: SessionSummary, client = new QueryClient({ defaultOptions: { queries: { retry: false } } }), findings = 0) {
  const root = createRootRoute({
    component: () => (
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={session}>
          <ShellCounts />
          <Notifications onClose={() => undefined} findings={findings} />
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  const router = createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) });
  render(<RouterProvider router={router} />);
  return client;
}

function shell(session: SessionSummary) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
    createRoute({ getParentRoute: () => root, path: entry.to, component: () => <PageHeading title={entry.label} /> }),
  );
  const router = createRouter({ routeTree: root.addChildren(pages), history: createMemoryHistory({ initialEntries: ["/"] }) });
  render(<RouterProvider router={router} />);
}

const asked = (seen: Asked[], view: string) => seen.filter((request) => request.path === "/api/console/v1/approvals" && request.query.get("view") === view);
const overviews = (seen: Asked[]) => seen.filter((request) => request.path === "/api/console/v1/overview");

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("the bell's panel (NV4, #678)", () => {
  it("tells an approver how many approvals wait, when the soonest lapses, and why they are theirs", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    const seen = gateway({ "GET /api/console/v1/approvals?view=pending": queue(2), "GET /api/console/v1/account": ACCOUNT });
    panel(approver);
    const waiting = await screen.findByRole("region", { name: "Waiting on you" });
    expect(await within(waiting).findByText("2 approvals waiting for your decision")).toBeInTheDocument();
    expect(within(waiting).getByText("The soonest lapses in 3:12")).toBeInTheDocument();
    expect(within(waiting).getByText("You are an assigned approver.")).toBeInTheDocument();
    expect(within(waiting).getByRole("link", { name: "Open Approvals" })).toHaveAttribute("href", "/approvals");
    // An approver's panel never asks for what the route refuses them, nor for the overview.
    expect(asked(seen, "others")).toHaveLength(0);
    expect(overviews(seen)).toHaveLength(0);
  });

  it("adds an administrator's findings, the approvals held for others and the unsettled dispatches", async () => {
    gateway({
      "GET /api/console/v1/approvals?view=pending": queue(1),
      "GET /api/console/v1/approvals?view=others": queue(4),
      "GET /api/console/v1/overview": { body: overview },
      "GET /api/console/v1/account": ACCOUNT,
    });
    panel(admin, undefined, 3);
    const waiting = await screen.findByRole("region", { name: "Waiting on you" });
    expect(await within(waiting).findByText("3 open monitoring findings")).toBeInTheDocument();
    expect(within(waiting).getByRole("link", { name: "Review findings" })).toHaveAttribute("href", "/monitor?view=findings");
    expect(await within(waiting).findByText("4 approvals waiting on other approvers")).toBeInTheDocument();
    expect(within(waiting).getByText("Held for approvers in the spaces you are looking at. You are not assigned to decide these.")).toBeInTheDocument();
    expect(within(waiting).getByRole("link", { name: "Show waiting on others" })).toHaveAttribute("href", "/approvals?view=others");
    expect(await within(waiting).findByText("2 dispatches awaiting provider evidence")).toBeInTheDocument();
    expect(within(waiting).getByRole("link", { name: "See uncertain requests" })).toHaveAttribute("href", "/activity?state=UNCERTAIN");
    // Neither figure is windowed, so no row names a period.
    expect(waiting.textContent).not.toMatch(/\b(days?|last|hours?|week)\b/i);
  });

  it("reads 50+ for the approvals held for others when there is a next page", async () => {
    gateway({
      "GET /api/console/v1/approvals?view=pending": queue(0),
      "GET /api/console/v1/approvals?view=others": queue(50, "next"),
      "GET /api/console/v1/overview": { body: { ...overview, unsettled: 0 } },
      "GET /api/console/v1/account": ACCOUNT,
    });
    panel(admin);
    expect(await screen.findByText("50+ approvals waiting on other approvers")).toBeInTheDocument();
  });

  it("renders the administrator's figures from the entries Home and the Approvals page already hold", async () => {
    const held = new Promise<{ status?: number; body: unknown }>(() => undefined);
    gateway({
      "GET /api/console/v1/approvals?view=pending": queue(0),
      "GET /api/console/v1/approvals?view=others": () => held,
      "GET /api/console/v1/overview": () => held,
      "GET /api/console/v1/account": ACCOUNT,
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } });
    client.setQueryData(readOverviewQueryKey({ query: { range: "7d", utc_offset: "0" } }), { ...overview, unsettled: 5 });
    client.setQueryData(listApprovalsQueryKey({ query: { view: "others" } }), (queue(3) as { body: unknown }).body);
    panel(admin, client);
    expect(await screen.findByText("5 dispatches awaiting provider evidence")).toBeInTheDocument();
    expect(screen.getByText("3 approvals waiting on other approvers")).toBeInTheDocument();
  });

  it("only links: no control decides, settles, stops or resumes, and every link is one of four pages", async () => {
    gateway({
      "GET /api/console/v1/approvals?view=pending": queue(1),
      "GET /api/console/v1/approvals?view=others": queue(1),
      "GET /api/console/v1/overview": { body: { ...overview, unsettled: 1 } },
      "GET /api/console/v1/account": ACCOUNT,
    });
    panel(admin, undefined, 1);
    const waiting = await screen.findByRole("region", { name: "Waiting on you" });
    await within(waiting).findByText("1 dispatch awaiting provider evidence");
    await within(waiting).findByText("1 approval waiting on other approvers");
    await within(waiting).findByText("1 open monitoring finding");
    const dialog = screen.getByRole("dialog", { name: "Notifications" });
    for (const name of [/approve/i, /refuse/i, /settle/i, /stop/i, /resume/i]) {
      expect(within(dialog).queryByRole("button", { name })).toBeNull();
    }
    const hrefs = within(waiting).getAllByRole("link").map((link) => link.getAttribute("href"));
    expect(hrefs.sort()).toEqual(["/activity?state=UNCERTAIN", "/approvals", "/approvals?view=others", "/monitor?view=findings"].sort());
  });

  it("says nothing is waiting, and keeps the sign-in security log below without the old sentence", async () => {
    gateway({ "GET /api/console/v1/approvals?view=pending": queue(0), "GET /api/console/v1/account": ACCOUNT });
    panel(approver);
    expect(await screen.findByText("Nothing is waiting on you.")).toBeInTheDocument();
    const security = screen.getByRole("region", { name: "Sign-in security" });
    expect(await within(security).findByText("A second factor was added.")).toBeInTheDocument();
    expect(security).not.toHaveTextContent("Approval requests appear on the Approvals page.");
  });
});

describe("the bell (NV4, #678)", () => {
  it("counts an approver's assigned approvals in its name and shows a dot", async () => {
    gateway({ "GET /api/console/v1/approvals?view=pending": queue(2) });
    shell(approver);
    const bell = await screen.findByRole("button", { name: "Notifications, 2 waiting on you" });
    expect(bell.querySelector(".bell-dot")).toHaveAttribute("aria-hidden", "true");
  });

  it("counts an administrator's approvals and findings, never the approvals held for others", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const seen = gateway({
      "GET /api/console/v1/approvals?view=pending": queue(1),
      "GET /api/console/v1/approvals?view=others": queue(4),
      "GET /api/console/v1/overview": { body: overview },
      "GET /api/console/v1/tenant": tenant(3),
      "GET /api/console/v1/account": ACCOUNT,
    });
    shell(admin);
    const bell = await screen.findByRole("button", { name: "Notifications, 4 waiting on you" });
    // The administrator's further reads wait for the panel.
    expect(asked(seen, "others")).toHaveLength(0);
    expect(overviews(seen)).toHaveLength(0);
    await userEvent.click(bell);
    await screen.findByText("4 approvals waiting on other approvers");
    await waitFor(() => {
      expect(overviews(seen)).toHaveLength(1);
    });
    expect(asked(seen, "others")).toHaveLength(1);
    expect(overviews(seen)[0]?.query.get("range")).toBe("7d");
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Notifications" })).toBeNull();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(asked(seen, "others")).toHaveLength(1);
    expect(overviews(seen)).toHaveLength(1);
  });

  it("shows no dot and a plain name when nothing waits", async () => {
    gateway({ "GET /api/console/v1/approvals?view=pending": queue(0) });
    shell(approver);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const bell = screen.getByRole("button", { name: "Notifications" });
    expect(bell.querySelector(".bell-dot")).toBeNull();
  });
});
