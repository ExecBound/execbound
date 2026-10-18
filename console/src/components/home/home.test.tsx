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
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ReportView } from "../../api/types.gen";
import { POLL_MS } from "../../lib/poll";
import { serve } from "../../test/api";
import { REPORT } from "../../test/report";
import * as value from "./value";
import { ValueCard } from "./ValueCard";

function mount(element: ReactNode) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) => createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([page("/", element), page("/activity", <p>Activity</p>), page("/report", <p>Report</p>)]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function search(link: HTMLElement): Record<string, string> {
  return Object.fromEntries(new URL(link.getAttribute("href") ?? "", "http://console.test").searchParams);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("What ExecBound did", () => {
  it("lists every count, each a link to the list it counts from the report's start", async () => {
    serve({ "/api/console/v1/report": REPORT });
    mount(<ValueCard range="7d" offset="0" />);
    const limit = await screen.findByRole("link", { name: "4 refused by an impact limit, open in Activity" });
    expect(search(limit)).toEqual({ outcome: "refused_limit", from: REPORT.since });
    expect(search(screen.getByRole("link", { name: "6 refused by policy or a failed check, open in Activity" }))).toEqual({
      outcome: "refused_policy",
      from: REPORT.since,
    });
    // A top action narrows the same list by its action.
    const top = screen.getByRole("link", { name: "4 refused by policy or a failed check, Isolate endpoint, open in Activity" });
    expect(search(top)).toEqual({ outcome: "refused_policy", from: REPORT.since, action: "endpoint.isolate" });
    expect(search(screen.getByRole("link", { name: "2 lapsed before a decision, open in Activity" }))).toEqual({
      outcome: "lapsed",
      from: REPORT.since,
    });
    expect(screen.getByRole("link", { name: "1 approved, not used before the deadline, open in Activity" })).toBeInTheDocument();
    // Shown only above zero.
    expect(screen.queryByText("closed without a decision")).toBeNull();
    expect(screen.getByText("Refused because another request held the target")).toBeInTheDocument();
    expect(screen.getByText("Median time to decide: 3 min")).toBeInTheDocument();
    // A refusal before a decision has no Activity record, so no link.
    const before = screen.getByText("Refused before a decision (no Activity record)").closest("div");
    if (before === null) throw new Error("No refusal row");
    expect(within(before).queryByRole("link")).toBeNull();
    expect(within(before).getByText("3")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Full report" })).toHaveAttribute("href", "/report?range=7d");
    expect(screen.getByText(/Requests made since/)).toHaveTextContent("All spaces");
    // Observe mode has nothing to say here.
    expect(screen.queryByText("Observe mode: nothing was enforced")).toBeNull();
  });

  it("keeps observe mode's counts apart from every enforced count", async () => {
    const watched: ReportView = {
      ...REPORT,
      observed: { total: 7, would_refuse: 3, would_refuse_by_limit: 1, would_hold: 2, would_run: 2 },
    };
    serve({ "/api/console/v1/report": watched });
    mount(<ValueCard range="7d" offset="0" />);
    const section = (await screen.findByRole("heading", { name: "Observe mode: nothing was enforced" })).closest("section");
    if (section === null) throw new Error("No observe section");
    expect(within(section).getByRole("link", { name: "3 would have been refused, open in Activity" })).toBeInTheDocument();
    expect(within(section).getByRole("link", { name: "1 would have been refused by a limit, open in Activity" })).toBeInTheDocument();
    expect(within(section).queryByText(/refused by an impact limit/)).toBeNull();
  });

  it("uses none of the words a value report never uses (HV17)", async () => {
    serve({ "/api/console/v1/report": { ...REPORT, observed: { total: 1, would_refuse: 1, would_refuse_by_limit: 0, would_hold: 0, would_run: 0 } } });
    mount(<ValueCard range="7d" offset="0" />);
    await screen.findByRole("link", { name: "Full report" });
    const strings: string[] = [];
    const collect = (item: unknown) => {
      if (typeof item === "string") strings.push(item);
      else if (item !== null && typeof item === "object") Object.values(item).forEach(collect);
    };
    collect(value);
    collect(value.rows(REPORT));
    collect(value.observed(REPORT));
    // The one disclaimer names harm prevented only to say a refusal is no proof of it.
    const words = [document.body.textContent, ...strings].map((text) => text.replace(value.DISCLAIMER, "").toLowerCase());
    for (const banned of ["prevent", "attack", "threat", "blocked"]) {
      expect(words.filter((text) => text.includes(banned))).toEqual([]);
    }
    expect(document.body.textContent).toContain(value.DISCLAIMER);
  });

  it("reads the report once and does not poll it", async () => {
    vi.useFakeTimers();
    try {
      const calls = serve({ "/api/console/v1/report": REPORT });
      mount(<ValueCard range="7d" offset="0" />);
      await vi.waitFor(() => {
        expect(calls.filter((call) => call.method === "GET" && call.path === "/api/console/v1/report")).toHaveLength(1);
      });
      await vi.advanceTimersByTimeAsync(POLL_MS * 3);
      expect(calls.filter((call) => call.method === "GET" && call.path === "/api/console/v1/report")).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
