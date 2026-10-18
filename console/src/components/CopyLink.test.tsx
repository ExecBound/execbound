// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { serve } from "../test/api";
import { CopyLink, CopyText } from "./CopyLink";
import { ExecutionDrawer } from "./ExecutionDrawer";

const RECORD = "44444444-0000-4000-8000-000000000001";
const AGENT = "55555555-0000-4000-8000-000000000002";

/** `element` on a page whose address bar holds more than the route: a cursor and a secret-shaped
 * key the copied link must never carry. */
function mount(element: ReactNode, initial = `/activity?cursor=abc&token=hunter2&open=${RECORD}`) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) => createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([page("/activity", element), page("/agents/$agentId", element)]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

function clipboard(write: (value: string) => Promise<void>) {
  const writeText = vi.fn(write);
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
  return writeText;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Copy link and Copy reference (#678)", () => {
  it("copies the router's address for the record on this origin, never the address bar", async () => {
    const writeText = clipboard(() => Promise.resolve());
    mount(<CopyLink to="/activity" search={{ open: RECORD }} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activity?open=${RECORD}`);
    expect(screen.getByRole("status")).toHaveTextContent("Link copied.");
  });

  it("copies an agent's page by its identifier", async () => {
    const writeText = clipboard(() => Promise.resolve());
    mount(<CopyLink to="/agents/$agentId" params={{ agentId: AGENT }} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/agents/${AGENT}`);
  });

  it("shows the link as text to copy by hand when the clipboard refuses", async () => {
    clipboard(() => Promise.reject(new Error("denied")));
    mount(<CopyLink to="/activity" search={{ open: RECORD }} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    expect(screen.getByRole("status")).toHaveTextContent(`Copy this link: ${window.location.origin}/activity?open=${RECORD}`);
  });

  it("copies a reference, and says so", async () => {
    const writeText = clipboard(() => Promise.resolve());
    mount(<CopyText value="EB-7" />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy reference" }));
    expect(writeText).toHaveBeenCalledWith("EB-7");
    expect(screen.getByRole("status")).toHaveTextContent("Reference copied.");
  });

  it("puts both in the record drawer: the reference, and Activity's link to the record", async () => {
    const writeText = clipboard(() => Promise.resolve());
    serve({
      [`/api/console/v1/executions/${RECORD}`]: {
        request_ref: "EB-7",
        external_case: null,
        execution_id: RECORD,
        created_at: "2026-09-24T10:05:00Z",
        changed_at: "2026-09-24T10:05:01Z",
        state: "EXECUTED",
        state_label: "Executed",
        action: "endpoint.isolate",
        action_label: "Isolate endpoint",
        target: { canonical_target_id: "c-7", provider_id: "sample-ws-dev-01", resource_class: "workstation", environment: "development", sample: true },
        agent: { principal_id: "p-agent", label: null, kind: "AGENT", number: 1 },
        approval: null,
        reasons: [],
        reconcile: { available: false, kind: null, continuation: null },
        timeline: [], arguments: [], facts: [], obligations: [], limits: [], checkpoint: [], carriers: [], deliveries: [],
        related_requests: [], dispatch: null, observed_effect: null, plan_hash: "ab".repeat(32), valid_until: "2026-09-24T10:05:00Z",
        bundle_id: null, policy_readable: false,
      },
    });
    mount(<ExecutionDrawer executionId={RECORD} onClose={() => undefined} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy reference" }));
    expect(writeText).toHaveBeenLastCalledWith("EB-7");
    await userEvent.click(screen.getByRole("button", { name: "Copy link" }));
    expect(writeText).toHaveBeenLastCalledWith(`${window.location.origin}/activity?open=${RECORD}`);
  });
});
