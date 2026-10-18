// SPDX-License-Identifier: AGPL-3.0-only
// The pages that name themselves, through the application's own routes (NV9, #678): the crumb is
// the name the page's heading prints, the ancestors are links, and a page this deployment does
// not have is named Not found rather than by its navigation entry.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentDetail, SessionView } from "../api/types.gen";
import { NotFound } from "../components/NotFound";
import { NO_SERVICE } from "../lib/session";
import { routeTree } from "../routeTree.gen";
import { serve } from "../test/api";

const AGENT = "22222222-2222-4222-8222-222222222222";

const session: SessionView = {
  generation: "test-generation",
  can_switch_workspaces: false,
  access: {
    managed: false,
    roles: ["administrator"],
    permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"],
    workspace_permissions: [],
    space_permissions: {},
  },
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
  invitations: false,
  mail: true,
  features: [],
  service: NO_SERVICE,
};

const AGENT_DETAIL: AgentDetail = {
  row_id: AGENT,
  kind: "principal",
  agent: { principal_id: AGENT, active: true, dormant: false, label: null, number: 3, created_at: "2026-10-01T08:00:00Z", deactivated_at: null },
  binding: null,
  discovered: null,
  credentials: [],
  recent: [],
  runs: [],
  more_runs: false,
  groups: [],
  requests: 0,
  month: "2026-10-01T00:00:00Z",
  bundle: true,
  observe: false,
  limits: [],
  reach: [],
  rules_bundle_id: null,
  options: [],
};

function mount(initial: string, answers: Record<string, unknown> = {}) {
  serve({ "/api/console/v1/session": session, ...answers });
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [initial] }),
    defaultNotFoundComponent: NotFound,
  });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

async function current(): Promise<string> {
  const crumbs = await screen.findByRole("navigation", { name: "Breadcrumb" });
  let text = "";
  await waitFor(() => {
    const item = within(crumbs).getAllByRole("listitem").find((li) => li.getAttribute("aria-current") === "page");
    text = item?.textContent ?? "";
    expect(text).not.toBe("");
  });
  return text;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a page's own name in the breadcrumb", () => {
  it("names Ask Not found where the deployment has no assistant, never Ask", async () => {
    mount("/ask");
    await screen.findByRole("heading", { level: 1, name: "There is no page here" });
    await waitFor(async () => {
      expect(await current()).toBe("Not found");
    });
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).queryByText("Ask")).toBeNull();
  });

  it.each([
    ["an unlabelled agent by its number", AGENT_DETAIL, "Agent 3"],
    ["a labelled agent by its label", { ...AGENT_DETAIL, agent: { ...AGENT_DETAIL.agent, label: "Triage bot" } }, "Triage bot"],
    [
      "a discovered agent by the directory's name",
      {
        ...AGENT_DETAIL,
        kind: "discovered" as const,
        agent: null,
        discovered: {
          agent: {
            agent_id: AGENT,
            platform_ref: "sp-0002",
            identity_class: "agent_identity",
            class_label: "agent identity",
            source_label: "Entra",
            display_name: "svc-backup@corp.example",
            enabled: true,
            blueprint_ref: null,
            credential_kinds: [],
            sponsors: [],
            sponsor_state: "read",
            first_seen_at: "2026-09-18T09:00:00Z",
            observed_at: "2026-09-19T12:00:00Z",
            gone_at: null,
          },
          findings: [],
          observations: [],
        },
      },
      "svc-backup@corp.example",
    ],
  ])("names %s, as its heading does, under Agent connections", async (_case, detail, name) => {
    mount(`/agents/${AGENT}`, { [`/api/console/v1/agents/${AGENT}`]: detail });
    const heading = await screen.findByRole("heading", { level: 1, name });
    await waitFor(async () => {
      expect(await current()).toBe(heading.textContent);
    });
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "Agent connections" })).toHaveAttribute("href", "/agents");
  });
});
