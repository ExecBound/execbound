// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SessionView } from "../api/types.gen";
import { NO_SERVICE } from "../lib/session";
import { resetWorkspace } from "../lib/workspace-context";
import { routeTree } from "../routeTree.gen";
import { called, serve } from "../test/api";
import { REPORT } from "../test/report";

const session: SessionView = {
  generation: "gen-7", can_switch_workspaces: false,
  access: { managed: false, roles: ["administrator"], permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
  identity: { principal_id: "p-admin", kind: "ADMIN", label: "A. Rivera" },
  tenant: { tenant_id: "t-1", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
  csrf_token: "token",
  release: null,
  expires_at: "2026-09-19T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in",
  stop: null,
  space: null,
  spaces: 1,
  all_spaces: false,
  assistant: false,
  invitations: false, mail: true,
  features: [],
  service: NO_SERVICE,
};

function mount(initial = "/report") {
  resetWorkspace();
  const calls = serve({ "/api/console/v1/session": session, "/api/console/v1/report": REPORT });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initial] }) });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { calls, router };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the report page", () => {
  it("states its scope, prints, and downloads the same read as a CSV", async () => {
    resetWorkspace();
    const print = vi.spyOn(window, "print").mockImplementation(() => undefined);
    const user = userEvent.setup();
    const { calls } = mount();
    await screen.findByRole("heading", { level: 1, name: "What ExecBound did" });
    expect(await screen.findByText("Requests made in the last 7 days in all spaces, as ExecBound recorded them.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "7 days" })).toHaveAttribute("aria-pressed", "true");
    await screen.findByText("Refused by an impact limit");
    const link = screen.getByRole("link", { name: "Download CSV" });
    const href = new URL(link.getAttribute("href") ?? "", "http://console.test");
    expect(href.pathname).toBe("/api/console/v1/report.csv");
    expect([...href.searchParams.keys()].sort()).toEqual(["generation", "range", "utc_offset"]);
    expect(href.searchParams.get("range")).toBe("7d");
    expect(href.searchParams.get("generation")).toBe("gen-7");
    expect(href.searchParams.get("utc_offset")).toMatch(/^-?\d+$/);
    await user.click(screen.getByRole("button", { name: "Print" }));
    expect(print).toHaveBeenCalledOnce();
    expect(called(calls, "GET", "/api/console/v1/report", "?range=7d")).toBe(true);
  });

  it("drops a range it does not know and reads the default", async () => {
    const { calls } = mount("/report?range=1y");
    await screen.findByRole("heading", { level: 1, name: "What ExecBound did" });
    await screen.findByText("Refused by an impact limit");
    expect(called(calls, "GET", "/api/console/v1/report", "?range=7d")).toBe(true);
    expect(called(calls, "GET", "/api/console/v1/report", "?range=1y")).toBe(false);
  });

  it("names itself in the breadcrumb and the tab, not as the console (#678)", async () => {
    mount();
    await screen.findByRole("heading", { level: 1, name: "What ExecBound did" });
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    await waitFor(() => {
      const current = within(crumbs).getAllByRole("listitem").find((item) => item.getAttribute("aria-current") === "page");
      expect(current).toHaveTextContent(/^What ExecBound did$/);
    });
    expect(crumbs).not.toHaveTextContent("Console");
    await waitFor(() => {
      expect(document.title).toBe("What ExecBound did · Acme SOC · ExecBound");
    });
  });
});
