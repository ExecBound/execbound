// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readAccountOptions } from "../api/@tanstack/react-query.gen";
import { PageHeading } from "../components/ui/PageHeading";
import { forgetRelease, RELEASE_HEADER, RELEASE_META } from "../lib/release";
import { SessionContext, type SessionSummary } from "../lib/session";
import { serve } from "../test/api";
import { Shell } from "./Shell";

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

/** A page that reads through the generated client, whose runtime configuration checks every
 * response's release header against the one the build carries. */
function Reading() {
  const account = useQuery(readAccountOptions());
  return (
    <>
      <PageHeading title="Home" />
      <p>{account.isSuccess ? "The page read its data." : "Reading."}</p>
    </>
  );
}

function mount() {
  const rootRoute = createRootRoute({
    component: () => (
      <SessionContext.Provider value={admin}>
        <Shell>
          <Outlet />
        </Shell>
      </SessionContext.Provider>
    ),
  });
  const home = createRoute({ getParentRoute: () => rootRoute, path: "/", component: Reading });
  const activity = createRoute({
    getParentRoute: () => rootRoute,
    path: "/activity",
    component: () => <PageHeading title="Activity" />,
  });
  const router = createRouter({
    routeTree: rootRoute.addChildren([home, activity]),
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

let meta: HTMLMetaElement;

beforeEach(() => {
  meta = document.createElement("meta");
  meta.setAttribute("name", RELEASE_META);
  meta.setAttribute("content", "built-1111");
  document.head.append(meta);
});

afterEach(() => {
  meta.remove();
  forgetRelease();
  vi.unstubAllGlobals();
});

describe("a newer release behind the console", () => {
  it("shows the banner in the shell, and loads the new build on the next change of page (NV18, #678)", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { assign, reload: vi.fn(), origin: window.location.origin, href: window.location.href });
    serve({
      "/api/console/v1/account": () =>
        new Response(JSON.stringify({}), {
          headers: { "content-type": "application/json", [RELEASE_HEADER]: "served-2222" },
        }),
    });
    const router = mount();
    // The response that carried the newer release still reached the page.
    expect(await screen.findByText("The page read its data.")).toBeInTheDocument();
    // The shell has other live regions, so the banner is found by what it says.
    const sentence = await screen.findByText("A new version of ExecBound is available. It loads when you next change page.");
    const banner = sentence.closest<HTMLElement>('[role="status"]');
    if (banner === null) throw new Error("the banner is not a status region");
    expect(within(banner).getByRole("button", { name: "Reload" })).toBeInTheDocument();
    // The shell's after-paint layer, which holds the release navigation, is in place.
    await waitFor(() => {
      expect(document.querySelector("[data-announcer]")).not.toBeNull();
    });
    // The next change of page is the browser's own navigation, so the new build loads with it.
    const activity = screen.getAllByRole("link", { name: /Activity/ })[0];
    if (activity === undefined) throw new Error("the shell has no Activity link");
    await userEvent.click(activity);
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/activity");
    });
    expect(router.state.location.pathname).toBe("/");
    expect(screen.queryByRole("heading", { level: 1, name: "Activity" })).toBeNull();
  });

  it("says nothing when the server runs the build's own release", async () => {
    serve({
      "/api/console/v1/account": () =>
        new Response(JSON.stringify({}), {
          headers: { "content-type": "application/json", [RELEASE_HEADER]: "built-1111" },
        }),
    });
    mount();
    expect(await screen.findByText("The page read its data.")).toBeInTheDocument();
    expect(screen.queryByText(/A new version of ExecBound is available/)).toBeNull();
  });
});
