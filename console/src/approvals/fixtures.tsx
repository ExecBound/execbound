// SPDX-License-Identifier: AGPL-3.0-only
// What the approval page tests share: one item, one detail, the sessions that read them, and a
// gateway stand-in that answers by path and query, so a view's own read can be told apart.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
  stripSearchParams,
} from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { vi } from "vitest";

import { client } from "../api/client.gen";
import type { ApprovalDetail, ApprovalItem } from "../api/types.gen";
import { holdCsrfToken } from "../lib/client-config";
import { Toaster } from "../components/ui/Toast";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";
import { RoutedApprovals } from "./RoutedApprovals";
import { DEFAULT_APPROVALS_SEARCH, parseApprovalsSearch, type ApprovalsSearch } from "./search";

export const APPROVAL = "4b1e90c2-0000-4000-8000-000000000001";
export const OTHER = "4b1e90c2-0000-4000-8000-000000000009";
export const SPACE_X = "5a5a5a5a-0000-4000-8000-00000000000a";
export const SPACE_Y = "5a5a5a5a-0000-4000-8000-00000000000b";
export const TARGET = "cccccccc-0000-4000-8000-000000000004";
export const HOSTILE = "<img src=x onerror=alert(1)>";

export function item(changes: Partial<ApprovalItem> = {}): ApprovalItem {
  return {
    request_ref: "EB-1042",
    external_case: null,
    approval_id: APPROVAL,
    execution_id: "5c2f91d3-0000-4000-8000-000000000002",
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    target: "ws25",
    resource_class: "workstation",
    environment: "production",
    agent: { principal_id: "aaaaaaaa-0000-4000-8000-000000000003", label: "triage-agent-a", number: 3 },
    notified: null,
    created_at: "2026-09-19T14:07:31Z",
    expires_at: "2099-01-01T00:00:00Z",
    total_seconds: 720,
    deadline_clock: "approval deadline",
    approval_state: "PENDING",
    execution_state: "PENDING_APPROVAL",
    execution_state_label: "Held",
    required: 1,
    recorded: 0,
    mine: null,
    decided_at: null,
    reviewers: null,
    reviewers_left: null,
    assigned_to_you: null,
    delivery: null,
    ...changes,
  };
}

export function detail(changes: Partial<ApprovalDetail> = {}): ApprovalDetail {
  return {
    item: item(),
    deliveries: [],
    related_requests: [],
    timeline: [{ at: "2026-09-19T14:07:31Z", kind: "transition", state: "PENDING_APPROVAL", sentence: "Held for a person.", actor: null }],
    status: "pending",
    sentence: "Isolate endpoint on ws25.",
    plan_hash: "ab".repeat(32),
    canonical_target_id: TARGET,
    arguments: [],
    facts: [],
    obligations: [],
    quorum: { required: 1, recorded: 0, decisions: [], mine: null },
    deadline: { created_at: "2026-09-19T14:07:31Z", expires_at: "2099-01-01T00:00:00Z", total_seconds: 720, clock: "approval deadline" },
    effect: {
      sentence: "If approved, ExecBound sends contain to mock_crowdstrike for ws25 once. Reversible by Lift endpoint isolation.",
      provider: "mock_crowdstrike",
      provider_operation: "contain",
      resource_version: "r-7",
      mapping_version: "map-v1",
      precondition: null,
      reversible: true,
      reversed_by: "Lift endpoint isolation",
    },
    limits: [],
    notices: [],
    mode: "ENFORCE",
    stop: null,
    space: null,
    reviewing: true,
    your_review_elsewhere: null,
    link_path: `/approvals/${APPROVAL}`,
    continuation: "token",
    server_time: "2026-09-19T14:10:00Z",
    ...changes,
  };
}

/** An administrator of a one-space workspace who has not verified a factor recently. */
export const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"],
  mode: "ENFORCE",
  tenant: { id: "7f8e9d0c-0000-4000-8000-000000000003", name: "Synthetic SOC", detail: "" },
  person: { label: "A. Rivera", detail: "Administrator", initials: "", id: "dddddddd-0000-4000-8000-00000000000a" },
  csrf: "token",
};

export const APPROVER: SessionSummary = {
  ...ADMIN,
  role: "APPROVER",
  permissions: ["console.read", "approvals.decide"],
  person: { label: "B. Chen", detail: "Approver", initials: "", id: "dddddddd-0000-4000-8000-00000000000b" },
};

export interface Asked {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

export type Reply = { status?: number; body: unknown } | ((request: Asked) => { status?: number; body: unknown } | Promise<{ status?: number; body: unknown }>);

/**
 * Answers `"METHOD /path"` or `"METHOD /path?view=x"`, the query-specific key first; anything
 * else is a 404 refusal. Every request is recorded with its query.
 */
export function gateway(routes: Record<string, Reply>): Asked[] {
  const seen: Asked[] = [];
  holdCsrfToken("token-under-test");
  client.setConfig({ baseUrl: "http://console.test" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string) => {
      const request = input instanceof Request ? input : new Request(input);
      const url = new URL(request.url);
      const text = request.method === "GET" ? "" : await request.text();
      const record: Asked = {
        method: request.method,
        path: url.pathname,
        query: url.searchParams,
        body: text === "" ? undefined : (JSON.parse(text) as unknown),
      };
      seen.push(record);
      const view = url.searchParams.get("view");
      const answer =
        (view !== null ? routes[`${request.method} ${url.pathname}?view=${view}`] : undefined) ??
        routes[`${request.method} ${url.pathname}`];
      const resolved =
        answer === undefined
          ? { status: 404, body: { code: "NOT_FOUND", detail: "There is nothing here." } }
          : typeof answer === "function"
            ? await answer(record)
            : answer;
      return new Response(JSON.stringify(resolved.body), {
        status: resolved.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  return seen;
}

export function list(items: ApprovalItem[]) {
  return { body: { view: "pending", items, next_cursor: null, server_time: "2026-09-19T14:10:00Z" } };
}

/** The two core approval routes as the route files declare them, in a memory router. */
export function routed(initial: string, session: SessionSummary) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 0 }, mutations: { retry: 0 } } });
  const root = createRootRoute({
    component: () => (
      <SessionContext.Provider value={session}>
        <QueryClientProvider client={queryClient}>
          <Outlet />
          <Toaster />
        </QueryClientProvider>
      </SessionContext.Provider>
    ),
  });
  const index = createRoute({
    getParentRoute: () => root,
    path: "/approvals",
    validateSearch: parseApprovalsSearch,
    search: { middlewares: [stripSearchParams<ApprovalsSearch>(DEFAULT_APPROVALS_SEARCH)] },
    component: () => <RoutedApprovals />,
  });
  const one = createRoute({
    getParentRoute: () => root,
    path: "/approvals/$approvalId",
    validateSearch: parseApprovalsSearch,
    search: { middlewares: [stripSearchParams<ApprovalsSearch>(DEFAULT_APPROVALS_SEARCH)] },
    component: function One() {
      return <RoutedApprovals selected={one.useParams().approvalId} />;
    },
  });
  const approvers = createRoute({ getParentRoute: () => root, path: "/approvers", component: () => <p>Who reviews</p> });
  const history = createMemoryHistory({ initialEntries: [initial] });
  const router = createRouter({ routeTree: root.addChildren([index, one, approvers]), history });
  render(<RouterProvider router={router} />);
  return { router, history };
}

