// SPDX-License-Identifier: AGPL-3.0-only
// Monitoring under test at an address (#678): the page behind a `/monitor` route that reads
// its search the way the real route does, so a link, a chip or a disclosure that writes the
// address re-renders the page from it, and the test can read where it went.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, useNavigate, useSearch } from "@tanstack/react-router";
import { render } from "@testing-library/react";

import { MonitorPage } from "../components/monitor/MonitorPage";
import { parseMonitorSearch } from "../components/monitor/search";
import { Toaster } from "../components/ui/Toast";
import { EditionContext, type Edition } from "../edition/context";
import { edition as core } from "../edition/core";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";

export const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };

function Monitor() {
  const search = parseMonitorSearch(useSearch({ strict: false }));
  const navigate = useNavigate();
  // As the real route does: closing setup takes `setup` out of the address.
  return (
    <MonitorPage
      {...search}
      onSetupClosed={() => {
        void navigate({ to: "/monitor", search: (previous: Record<string, unknown>) => ({ ...previous, setup: undefined }), replace: true });
      }}
      onConnectRead={() => {
        void navigate({ to: "/monitor", search: (previous: Record<string, unknown>) => ({ ...previous, connect: undefined }), replace: true });
      }}
    />
  );
}

export function renderMonitor(path: string, { session = ADMIN, edition = core }: { session?: SessionSummary; edition?: Edition } = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 0 }, mutations: { retry: 0 } } });
  const rootRoute = createRootRoute({
    component: () => (
      <SessionContext.Provider value={session}>
        <QueryClientProvider client={queryClient}>
          <EditionContext.Provider value={edition}>
            <Outlet />
            <Toaster />
          </EditionContext.Provider>
        </QueryClientProvider>
      </SessionContext.Provider>
    ),
  });
  const monitor = createRoute({
    getParentRoute: () => rootRoute,
    path: "/monitor",
    // As the real route does: the search passes through, and the page parses it.
    validateSearch: (search: Record<string, unknown>) => search,
    component: Monitor,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([monitor]),
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  return Object.assign(render(<RouterProvider router={router} />), { queryClient, router });
}
