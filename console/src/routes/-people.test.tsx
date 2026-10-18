// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SessionView } from "../api/types.gen";
import { NO_SERVICE } from "../lib/session";
import { routeTree } from "../routeTree.gen";
import { serve } from "../test/api";

function session(mail: boolean): SessionView {
  return {
    generation: "test-generation", can_switch_workspaces: false,
    access: { managed: false, roles: ["administrator"], permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
    identity: { principal_id: "p-admin", kind: "ADMIN", label: "A. Rivera" },
    tenant: { tenant_id: "t-1", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
    csrf_token: "token", release: null, expires_at: "2026-09-19T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in", stop: null,
    space: null, spaces: 1, all_spaces: false, assistant: false, invitations: false, mail, features: [],
    service: NO_SERVICE,
  };
}

/** Users, in the shell, for an administrator of a deployment with or without a mail relay. */
function mount(mail: boolean) {
  serve({
    "/api/console/v1/session": session(mail),
    "/api/console/v1/people": { people: [], next_cursor: null },
    "/api/console/v1/teammate-invitations": { invitations: [] },
  });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/people"] }) });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Inviting a teammate by email", () => {
  it("is offered where the deployment has a mail relay", async () => {
    mount(true);
    await screen.findByRole("heading", { level: 1, name: "Users" });
    expect(await screen.findByRole("button", { name: "Invite teammate" })).toBeInTheDocument();
    expect(screen.queryByText(/needs a mail relay/)).toBeNull();
  });

  it("is replaced by a pointer to Add user where it has none, since the email would never be sent", async () => {
    mount(false);
    await screen.findByRole("heading", { level: 1, name: "Users" });
    expect(await screen.findByText(/needs a mail relay, and this deployment has none/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Invite teammate" })).toBeNull();
    expect(screen.getByRole("button", { name: "Add user" })).toBeInTheDocument();
  });
});
