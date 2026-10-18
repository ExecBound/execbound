// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SampleStatusView, SessionView } from "../api/types.gen";
import { parseStep } from "../components/welcome/steps";
import { NO_SERVICE } from "../lib/session";
import { routeTree } from "../routeTree.gen";
import { serve } from "../test/api";
import { SETUP, setupView } from "../test/setup-view";

const SAMPLES: SampleStatusView = {
  state: "absent",
  offered: false,
  available: true,
  demo_available: false,
  demo_needs_refresh: false,
  bundle_id: null,
  hosts: [],
  observed_at: null,
  stale_at: null,
  first_request: null,
};

const SESSION: SessionView = {
  generation: "test-generation", can_switch_workspaces: false,
  access: { managed: false, roles: ["administrator"], permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
  identity: { principal_id: "p-admin", kind: "ADMIN", label: "A. Rivera" },
  tenant: { tenant_id: "t-1", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
  csrf_token: "token", release: null, expires_at: "2026-09-19T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in", stop: null,
  space: null, spaces: 1, all_spaces: false, assistant: false, invitations: false, mail: true, features: [],
  service: NO_SERVICE,
};

function mount(path: string) {
  serve({
    "/api/console/v1/session": SESSION,
    "/api/console/v1/samples": SAMPLES,
    [SETUP]: setupView({ policy: "done", agent_key: "done" }),
    "/api/console/v1/agents": { agents: [], next: null },
  });
  const history = createMemoryHistory({ initialEntries: [path] });
  const router = createRouter({ routeTree, history });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Getting started's step in the address (UX10, #678)", () => {
  it("admits a step only as one of the four", () => {
    expect(parseStep("verify")).toBe("verify");
    for (const value of ["foo", "Verify", "", ["verify"], 1, null, undefined]) expect(parseStep(value)).toBeUndefined();
  });

  it("opens the named step", async () => {
    const router = mount("/welcome?step=controls");
    expect(await screen.findByRole("heading", { name: "Choose your policy" })).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ step: "controls" });
  });

  it("opens an unknown step, handed through unchecked, on the opening step and writes it into the address", async () => {
    const router = mount("/welcome?step=foo");
    // The agent has a key and no request yet: Verify protection is the first step left.
    expect(await screen.findByRole("heading", { name: "Verify protection" })).toBeInTheDocument();
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ step: "verify" });
    });
  });
});
