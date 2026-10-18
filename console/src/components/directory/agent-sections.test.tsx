// SPDX-License-Identifier: AGPL-3.0-only
// The agent page's sections (#678, AK7 and AK8): one section at a time from `?section=`, a new
// agent opening on Connection, the connection steps folding once requests arrive, rules read
// as sentences with their effect, and each request linked to its record with its target.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

import type { AgentDetail } from "../../api/types.gen";
import { serve } from "../../test/api";
import { AgentDetailView, closestLimit, parseAgentSection, shownSection } from "./AgentDetail";

const AGENT = "22222222-2222-2222-2222-222222222222";
const KEY = "66666666-6666-6666-6666-666666666666";
const BUNDLE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const EXECUTION = "99999999-9999-9999-9999-999999999999";
const HOSTILE = "<img src=x onerror=alert(1)>";

const FRESH: AgentDetail = {
  row_id: AGENT,
  kind: "principal",
  agent: { principal_id: AGENT, active: true, dormant: false, label: "Triage bot", number: 3, created_at: "2026-10-01T08:00:00Z", deactivated_at: null },
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

const BUSY: AgentDetail = {
  ...FRESH,
  credentials: [
    { credential_id: KEY, number: 2, issued_at: "2026-10-01T08:00:00Z", expires_at: "2026-10-20T08:00:00Z", revoked_at: null, state: "live", failures: 0, last_used_at: "2026-10-08T11:00:00Z", replaced: false },
  ],
  recent: [
    { execution_id: EXECUTION, action: "endpoint.isolate", label: "Isolate endpoint", canonical_target_id: BUNDLE, target_label: HOSTILE, state: "EXECUTED", created_at: "2026-10-08T11:00:00Z", request_ref: "EB-12" },
  ],
  requests: 1,
  limits: [
    { scope: "Principal", budget: "autonomous", actions: "endpoint.isolate", labels: "isolate", window: "24 hours", count: 7, max_targets: 10, on_exceed: "DENY" },
    { scope: "Tenant", budget: "total", actions: "endpoint.isolate", labels: "isolate", window: "1 hour", count: 1, max_targets: 10, on_exceed: "DENY" },
  ],
};

function mount(element: ReactNode, initial = `/agents/${AGENT}`) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/agents/$agentId", element),
      page("/agents", <p>Agents</p>),
      page("/activity", <p>Activity</p>),
      page("/policy", <p>Policy</p>),
      page("/policy/$bundleId", <p>Bundle</p>),
      page("/policy/$bundleId/rules", <p>Rules</p>),
      page("/monitor", <p>Monitoring</p>),
    ]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

function strip() {
  return screen.getByRole("navigation", { name: "Agent sections" });
}

describe("the agent page's sections (AK7)", () => {
  it("keeps a known section from the address and drops anything else", () => {
    expect(parseAgentSection({ section: "permissions" })).toBe("permissions");
    expect(parseAgentSection({ section: "nope" })).toBeUndefined();
    expect(parseAgentSection({})).toBeUndefined();
    expect(parseAgentSection(null)).toBeUndefined();
    // Connection on an agent nothing governs is not a section it has: the default instead.
    const discovered: AgentDetail = { ...FRESH, kind: "discovered", agent: null };
    expect(shownSection(discovered, "connection")).toBe("overview");
    expect(shownSection(BUSY, undefined)).toBe("overview");
    expect(shownSection(FRESH, undefined)).toBe("connection");
  });

  it("opens a new agent on Connection with its steps and key form, and marks it current", async () => {
    serve({});
    mount(<AgentDetailView detail={FRESH} />);
    expect(await screen.findByRole("heading", { level: 2, name: "Connect this agent" })).toBeInTheDocument();
    expect(screen.getByLabelText("Issue an API key with a lifetime of")).toBeInTheDocument();
    const links = within(strip()).getAllByRole("link");
    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Connection", "Permissions", "Activity", "Advanced"]);
    expect(within(strip()).getByRole("link", { name: "Connection" })).toHaveAttribute("aria-current", "page");
    // Overview carries its section explicitly, so a new agent can reach it.
    expect(within(strip()).getByRole("link", { name: "Overview" })).toHaveAttribute("href", `/agents/${AGENT}?section=overview`);
    expect(screen.queryByRole("heading", { level: 2, name: "Summary" })).toBeNull();
  });

  it("opens an agent with requests on Overview, with a summary of what matters", async () => {
    serve({});
    mount(<AgentDetailView detail={BUSY} />);
    const summary = (await screen.findByRole("heading", { level: 2, name: "Summary" })).closest("section");
    if (summary === null) throw new Error("No summary");
    expect(within(strip()).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(within(summary).getByText("Last request").nextSibling).toHaveTextContent("2026-10-08");
    expect(within(summary).getByText("Live API keys").nextSibling).toHaveTextContent(/^1, the next expires/);
    expect(within(summary).getByText("Closest limit").nextSibling).toHaveTextContent("7 of 10 isolate targets in 24 hours");
    expect(screen.queryByRole("heading", { level: 2, name: "Connect this agent" })).toBeNull();
    expect(closestLimit([])).toBe("No impact limit applies");
    expect(closestLimit([{ ...BUSY.limits[1], count: 4 } as AgentDetail["limits"][number]])).toBe("No limit is close");
  });

  it("folds the connection steps into one line once requests arrive", async () => {
    serve({});
    mount(<AgentDetailView detail={BUSY} section="connection" />, `/agents/${AGENT}?section=connection`);
    expect(await screen.findByText(/^Connected: requests received, the last at/)).toBeInTheDocument();
    const steps = screen.getByText("Show the connection steps").closest("details");
    expect(steps).not.toHaveAttribute("open");
    await userEvent.click(screen.getByText("Show the connection steps"));
    expect(steps).toHaveAttribute("open");
    expect(within(steps ?? document.body).getByRole("heading", { level: 2, name: "Connect this agent" })).toBeVisible();
    // Step 3 opens this page's Permissions section, and a lost key is revoked below.
    expect(screen.getByRole("link", { name: "Review this agent’s Permissions" })).toHaveAttribute("href", `/agents/${AGENT}?section=permissions`);
    expect(screen.getByText(/Revoke a lost key in API keys below/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "API keys" })).toBeInTheDocument();
  });

  it("follows a section link to that section alone", async () => {
    serve({});
    const router = mount(<AgentDetailView detail={BUSY} />);
    await screen.findByRole("heading", { level: 2, name: "Summary" });
    await userEvent.click(within(strip()).getByRole("link", { name: "Activity" }));
    expect(router.state.location.search).toEqual({ section: "activity" });
  });

  it("offers a reader who does not administer the agent no change", async () => {
    serve({});
    mount(<AgentDetailView detail={{ ...BUSY, administered: false, agent: { ...BUSY.agent, label: null } as AgentDetail["agent"] }} />);
    expect(await screen.findByText(/it is changed by that Space's administrators/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save the label" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
    expect(within(strip()).queryByRole("link", { name: "Connection" })).toBeNull();
    cleanup();
    mount(<AgentDetailView detail={{ ...BUSY, administered: false }} section="advanced" />, `/agents/${AGENT}?section=advanced`);
    expect(await screen.findByRole("heading", { level: 2, name: "API keys" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Revoke key/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Rotate key/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deactivate this agent" })).toBeNull();
    expect(screen.queryByRole("heading", { level: 2, name: "Binding" })).toBeNull();
  });
});

describe("readable rules and linked activity (AK8)", () => {
  const reach = (rules: AgentDetail["reach"][number]["rules"]): AgentDetail["reach"] => [
    { action: "endpoint.isolate", label: "Isolate endpoint", path_kind: "execbound", path: "ExecBound, this agent's credentials", certainty: "inferred", mode: "native", freshness: "from the active bundle", govern: false, rules },
  ];
  const RULES = [
    { id: "isolate-workstation-open-critical", effect: "allow", description: "Allow endpoint.isolate when role is workstation." },
    { id: "isolate-never-domain-controller", effect: "deny", description: "Deny endpoint.isolate when role is domain_controller." },
  ];
  const DOCUMENT = { authorization_policies: "permit(principal, action, resource);", approval_policies: "", complete: true, rules: [] };

  it("reads a recognised seed's rules as sentences with their effect, linking the bundle, and keeps its exact text", async () => {
    serve({});
    mount(
      <AgentDetailView detail={{ ...BUSY, reach: reach(RULES), rules_bundle_id: BUNDLE, rules_origin: "recognized-seed", policy_document: DOCUMENT }} section="permissions" />,
      `/agents/${AGENT}?section=permissions`,
    );
    const table = await screen.findByRole("table", { name: /Rules are as they read/ });
    expect(within(table).getByText("Allow")).toHaveClass("badge-allow");
    expect(within(table).getByText("Deny")).toHaveClass("badge-deny");
    expect(table).toHaveTextContent("Allow isolating an endpoint when the target is a workstation.");
    expect(within(table).getByRole("link", { name: "isolate-workstation-open-critical" })).toHaveAttribute("href", `/policy/${BUNDLE}`);
    const exact = screen.getByText("Exact policy documents").closest("details");
    expect(exact).not.toHaveAttribute("open");
    expect(within(exact ?? document.body).getByText(DOCUMENT.authorization_policies)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Policy conditions" })).toBeNull();
  });

  it("links a ruleset's rules to its rules form", async () => {
    serve({});
    mount(
      <AgentDetailView detail={{ ...BUSY, reach: reach(RULES), rules_bundle_id: BUNDLE, rules_origin: "rules" }} section="permissions" />,
      `/agents/${AGENT}?section=permissions`,
    );
    const table = await screen.findByRole("table", { name: /Rules are as they read/ });
    expect(within(table).getByRole("link", { name: "isolate-never-domain-controller" })).toHaveAttribute("href", `/policy/${BUNDLE}/rules`);
    expect(screen.queryByText("Exact policy documents")).toBeNull();
  });

  it("links each request to its record once and shows its target as text", async () => {
    serve({});
    mount(<AgentDetailView detail={BUSY} section="activity" />, `/agents/${AGENT}?section=activity`);
    const card = (await screen.findByRole("heading", { level: 2, name: "Recent activity" })).closest("section");
    if (card === null) throw new Error("No card");
    const [, row] = within(card).getAllByRole("row");
    expect(within(row ?? card).getAllByRole("link")).toHaveLength(1);
    expect(within(row ?? card).getByRole("link", { name: "Isolate endpoint" })).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
    expect(row).toHaveTextContent(HOSTILE);
    expect(document.querySelector("img")).toBeNull();
  });
});
