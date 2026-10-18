// SPDX-License-Identifier: AGPL-3.0-only
// The Policy pages' shared test fixtures: one active bundle, one draft, a preview with one
// changed decision, a stubbed generated client and a router that mounts a page at an address.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";

import { client } from "../api/client.gen";
import type { BundleDetail, BundlePreviewView, PolicyComparison, PolicyPage } from "../api/types.gen";

export const ACTIVE = "11111111-1111-1111-1111-111111111111";
export const DRAFT = "22222222-2222-2222-2222-222222222222";
export const EXECUTION = "33333333-3333-3333-3333-333333333333";
export const ACCOUNT = "44444444-4444-4444-4444-444444444444";

export const PAGE: PolicyPage = {
  active: ACTIVE,
  bundles: [
    {
      bundle_id: DRAFT,
      content_hash: "d".repeat(64),
      state: "DRAFT",
      changed_at: "2026-09-19T09:15:00Z",
      active: false,
    },
    {
      bundle_id: ACTIVE,
      content_hash: "a".repeat(64),
      state: "ACTIVE",
      changed_at: "2026-09-19T08:00:00Z",
      active: true,
    },
  ],
};

export function detail(overrides: Partial<BundleDetail> = {}): BundleDetail {
  return {
    bundle_id: ACTIVE,
    content_hash: "a".repeat(64),
    state: "ACTIVE",
    active: true,
    changed_at: "2026-09-19T08:00:00Z",
    mappings: [
      {
        operation_ref: "endpoint.isolate",
        account_id: ACCOUNT,
        mapping_version: "map-v1",
        schema_version: "action.v1",
        context_contract_version: "endpoint.v1",
        observe_only: false,
        external_executor: false,
      },
    ],
    limits: [
      {
        rule_id: "tenant-isolation",
        scope: "tenant",
        scope_label: "Tenant",
        actions: ["endpoint.isolate"],
        labels: ["Isolate an endpoint"],
        window: "1 hour",
        window_seconds: 3600,
        max_targets: 20,
        budget: "total",
        on_exceed: "DENY",
        used: 8,
        counted: "every request in this tenant",
      },
      {
        rule_id: "principal-autonomous-isolation",
        scope: "principal",
        scope_label: "Principal",
        actions: ["endpoint.isolate"],
        labels: ["Isolate an endpoint"],
        window: "1 hour",
        window_seconds: 3600,
        max_targets: 10,
        budget: "autonomous",
        on_exceed: "REQUIRE_APPROVAL",
        used: null,
        counted: "each agent on its own",
      },
    ],
    quorum: [
      { rule_id: "two-for-production", obligation: "policy:policy0", required: 2, rule: "review-production" },
    ],
    context_settings: [],
    rules: [
      {
        id: "allow-workstations",
        action: "endpoint.isolate",
        effect: "ALLOW",
        sentence: "Allow endpoint.isolate when role is workstation.",
        note: null,
      },
      {
        id: "deny-domain-controllers",
        action: "endpoint.isolate",
        effect: "DENY",
        sentence: "Deny endpoint.isolate when role is domain_controller.",
        note: "<img src=x onerror=alert(1)>",
      },
    ],
    written_as_rules: true,
    compiled: {
      cedar_schema: "namespace ExecBound {}",
      authorization_policies: 'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource);',
      approval_policies: "",
    },
    ...overrides,
  };
}

export const PREVIEW: BundlePreviewView = {
  bundle_id: DRAFT,
  content_hash: "d".repeat(64),
  state: "DRAFT",
  window: "24h",
  window_seconds: 86400,
  available: true,
  scope: "workspace",
  considered: 3,
  baseline_effects: { ALLOW: 3 },
  candidate_effects: { DENY: 1, REQUIRE_APPROVAL: 2 },
  changed: [
    {
      execution_id: EXECUTION,
      action: "endpoint.isolate",
      semantic_time: "2026-09-19T07:40:00Z",
      baseline_effect: "ALLOW",
      baseline_reasons: [],
      candidate_effect: "REQUIRE_APPROVAL",
      candidate_reasons: ["approval.required"],
      rule_ids: ["review-production"],
      differences: [],
      required_approvers: 2,
    },
  ],
  complete: true,
  issues: [],
};

/** A comparison that compared nothing, which every detail that asks for one gets by default. */
export const NOT_COMPARED: PolicyComparison = {
  against: null,
  comparable: false,
  why_not: "no-active",
  rules: [],
  budgets: [],
  actions_added: [],
  actions_removed: [],
  actions: [],
  mappings: [],
  context: [],
  signals: [],
  wider: 0,
  narrower: 0,
  unclear: 0,
};

/** The generated client under a stubbed fetch; Node's Request needs an absolute address. A
 *  draft's detail also reads its comparison, which is answered here unless a test asks. */
export function stub(
  fetch: (request: Request) => Promise<Response>,
  comparison: PolicyComparison = NOT_COMPARED,
) {
  const answer = (request: Request) =>
    new URL(request.url).pathname.endsWith("/compare") ? Promise.resolve(json(comparison)) : fetch(request);
  client.setConfig({ baseUrl: "http://console.test/", fetch: answer as typeof globalThis.fetch });
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function mount(element: ReactNode, initial = "/policy", queryClient = new QueryClient()) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/policy", element),
      page("/policy/$bundleId", element),
      page("/activity", <p>Activity</p>),
    ]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

export function resetClient() {
  client.setConfig({ baseUrl: "/", fetch: undefined });
}

/** Before each test: every request but a comparison is unexpected unless the test stubs it. */
export function expectNoRequests() {
  stub(() => Promise.reject(new Error("unexpected request")));
}
