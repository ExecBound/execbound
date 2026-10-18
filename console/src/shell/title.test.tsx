// SPDX-License-Identifier: AGPL-3.0-only
// The document title (NV1 to NV3, #678): most specific first, only the console's own words and
// the page's title words, the waiting count from the pill's own query, and a polite announcement
// when more approvals arrive, never as a new space's count.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentDetail, ExecutionDetail, ExecutionPage, SessionView } from "../api/types.gen";
import { item } from "../approvals/fixtures";
import { Announcer } from "../lib/announce";
import { polling, POLL_MS } from "../lib/poll";
import { NO_SERVICE } from "../lib/session";
import { routeTree } from "../routeTree.gen";
import { serve } from "../test/api";
import { agentDetail } from "../test/monitor-data";
import { composeTitle, QUIET_MS, useCountAnnouncement } from "./title";
import { titleNoun, type TitleWord } from "./page-name";

const EXECUTION = "50c680b9-0000-4000-8000-000000000003";
const AGENT = "22222222-2222-4222-8222-222222222222";
const MONITORED = "aaaaaaaa-0000-4000-8000-000000000001";

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

const record: ExecutionDetail = {
  request_ref: "EB-1042",
  external_case: null,
  execution_id: EXECUTION,
  created_at: "2026-09-19T14:02:11Z",
  changed_at: "2026-09-19T14:02:11Z",
  state: "DENIED",
  state_label: "Denied",
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  target: { canonical_target_id: "c-1", provider_id: "ws-01.corp.example", resource_class: "workstation", environment: "production" },
  agent: { principal_id: "p-agent", label: "triage-agent-b", kind: "AGENT", number: 2 },
  approval: null,
  reasons: [],
  reconcile: { available: false, kind: null, continuation: null },
  deliveries: [],
  related_requests: [],
  bundle_id: "b-1",
  policy_readable: true,
  arguments: [],
  facts: [],
  obligations: [],
  limits: [],
  timeline: [],
  checkpoint: [],
  carriers: [],
  dispatch: null,
  observed_effect: null,
  plan_hash: "ab".repeat(32),
  valid_until: "2026-09-19T14:06:11Z",
};

const agent: AgentDetail = {
  row_id: AGENT,
  kind: "principal",
  agent: { principal_id: AGENT, active: true, dormant: false, label: "<img src=x onerror=alert(1)>", number: 1, created_at: "2026-10-01T08:00:00Z", deactivated_at: null },
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

function pending(count: number, next: string | null = null) {
  return {
    view: "pending",
    items: Array.from({ length: count }, (_, index) =>
      item({ approval_id: `4b1e90c2-0000-4000-8000-${String(index).padStart(12, "0")}`, request_ref: `EB-${String(index + 1)}` }),
    ),
    next_cursor: next,
    server_time: "2026-09-19T14:10:00Z",
  };
}

function mount(initial: string, answers: Record<string, unknown> = {}, view: SessionView = session) {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
  const page: ExecutionPage = { items: [record], next_cursor: null };
  serve({
    "/api/console/v1/session": view,
    "/api/console/v1/approvals": pending(0),
    "/api/console/v1/executions": page,
    [`/api/console/v1/executions/${EXECUTION}`]: record,
    ...answers,
  });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initial] }) });
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  document.title = "ExecBound";
});

describe("the document title (NV1, NV2, #678)", () => {
  it("counts the approvals waiting for this person, most specific first", async () => {
    mount("/approvals", { "/api/console/v1/approvals": pending(2) });
    await waitFor(() => {
      expect(document.title).toBe("(2) Approvals · Acme SOC · ExecBound");
    });
  });

  it("reads 50+ when the queue has a next page", async () => {
    mount("/approvals", { "/api/console/v1/approvals": pending(50, "next") });
    await waitFor(() => {
      expect(document.title).toBe("(50+) Approvals · Acme SOC · ExecBound");
    });
  });

  it("names an open record by its reference, never its target or its action", async () => {
    mount(`/activity?open=${EXECUTION}`, {}, { ...session, space: { space_id: "s-1", name: "Payments", archived: false }, spaces: 2 });
    await waitFor(() => {
      expect(document.title).toBe("EB-1042 · Activity · Payments · Acme SOC · ExecBound");
    });
    expect(document.title).not.toContain("ws-01");
    expect(document.title).not.toContain("Isolate");
  });

  it("names an agent by its number, never its label", async () => {
    mount(`/agents/${AGENT}`, { [`/api/console/v1/agents/${AGENT}`]: agent });
    await waitFor(() => {
      expect(document.title).toBe("Agent 1 · Agent connections · Acme SOC · ExecBound");
    });
    expect(document.title).not.toContain("img");
  });

  it("names a monitored agent by the console's own noun, never the directory's name", async () => {
    mount(`/monitor/agents/${MONITORED}`, {
      [`/api/console/v1/monitor/agents/${MONITORED}`]: agentDetail({ display_name: "svc-backup@corp.example" }),
    });
    await screen.findByRole("heading", { level: 1, name: "svc-backup@corp.example" });
    await waitFor(() => {
      expect(document.title).toBe("Monitored agent · Monitoring · Acme SOC · ExecBound");
    });
  });

  it("restores the product's name when the console unmounts", async () => {
    const view = mount("/approvals", { "/api/console/v1/approvals": pending(1) });
    await waitFor(() => {
      expect(document.title).toBe("(1) Approvals · Acme SOC · ExecBound");
    });
    view.unmount();
    expect(document.title).toBe("ExecBound");
  });

  it("composes no empty part and no doubled separator", () => {
    expect(
      composeTitle({ count: 0, more: false, words: [titleNoun("Not found")], section: undefined, space: undefined, workspace: "Acme SOC" }),
    ).toBe("Not found · Acme SOC · ExecBound");
    const words: TitleWord[] = [];
    expect(composeTitle({ count: undefined, more: false, words, section: "Home", space: "Payments", workspace: "Acme SOC" })).toBe(
      "Home · Payments · Acme SOC · ExecBound",
    );
  });

  it("asks for nothing while the tab is hidden", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mount("/approvals", { "/api/console/v1/approvals": pending(2) });
    await waitFor(() => {
      expect(document.title).toBe("(2) Approvals · Acme SOC · ExecBound");
    });
    const fetched = vi.mocked(fetch);
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
    expect(polling()).toBe(false);
    const before = fetched.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2 * POLL_MS);
    });
    expect(fetched.mock.calls.length).toBe(before);
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
});

describe("the waiting count's announcement (NV3, #678)", () => {
  function region(): Element {
    const found = document.querySelector("[data-announcer]");
    if (found === null) throw new Error("No announcer");
    return found;
  }

  async function settle(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  }

  it("says a rise once, after a second of quiet, and never the first read", async () => {
    vi.useFakeTimers();
    render(<Announcer />);
    const { rerender } = renderHook<undefined, { count: number | undefined; at: number }>(
      ({ count, at }) => {
        useCountAnnouncement(count, at, "t/");
        return undefined;
      },
      { initialProps: { count: 2, at: 1 } },
    );
    await settle(QUIET_MS + 50);
    expect(region()).toHaveTextContent("");
    rerender({ count: 3, at: 2 });
    await settle(300);
    rerender({ count: 4, at: 3 });
    await settle(QUIET_MS + 50);
    expect(region()).toHaveTextContent("4 approvals waiting for you");
    region().textContent = "";
    rerender({ count: 4, at: 4 });
    await settle(QUIET_MS + 50);
    expect(region()).toHaveTextContent("");
  });

  it("treats a new space's count as a first read, and a later rise there as a rise", async () => {
    vi.useFakeTimers();
    render(<Announcer />);
    const { rerender } = renderHook<undefined, { count: number | undefined; at: number; scope: string }>(
      ({ count, at, scope }) => {
        useCountAnnouncement(count, at, scope);
        return undefined;
      },
      { initialProps: { count: 2, at: 1, scope: "t/a" } },
    );
    // The switch lands before the new space's answer: the old answer is not a first read there.
    rerender({ count: 2, at: 1, scope: "t/b" });
    rerender({ count: undefined, at: 0, scope: "t/b" });
    rerender({ count: 5, at: 2, scope: "t/b" });
    await settle(QUIET_MS + 50);
    expect(region()).toHaveTextContent("");
    rerender({ count: 6, at: 3, scope: "t/b" });
    await settle(QUIET_MS + 50);
    expect(region()).toHaveTextContent("6 approvals waiting for you");
  });
});
