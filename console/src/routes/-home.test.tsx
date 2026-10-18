// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  ApprovalList,
  ExecutionDetail,
  ExecutionPage,
  ExecutionSummary,
  OverviewView,
  SessionView,
  Settings,
  UnroutedApprovals,
} from "../api/types.gen";
import { POLL_MS } from "../lib/poll";
import { NO_SERVICE } from "../lib/session";
import { dayLabel, ticks } from "../lib/days";
import { routeTree } from "../routeTree.gen";
import { called, json, serve, type Call } from "../test/api";
import { REPORT } from "../test/report";

const DENIED = "7c21e04b-0000-4000-8000-000000000001";
const HELD = "9a11e04b-0000-4000-8000-000000000002";
const NOW = "2026-09-19T14:02:11Z";

const session: SessionView = {
  generation: "test-generation", can_switch_workspaces: false,
  access: { managed: false, roles: ["administrator"], permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
  identity: { principal_id: "p-admin", kind: "ADMIN", label: "A. Rivera" },
  tenant: { tenant_id: "t-1", name: "Acme SOC", mode: "ENFORCE", approval_deadline_seconds: 900 },
  csrf_token: "token",
  release: null,
  expires_at: "2026-09-19T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in",
  stop: null,
  // A tenant that never made a second space: one space, no switcher entry.
  space: null,
  spaces: 1,
  all_spaces: false,
  assistant: false,
      invitations: false, mail: true,
      features: [],
  service: NO_SERVICE,
};

function bucket(index: number): OverviewView["series"][number] {
  const start = new Date(Date.parse("2026-09-12T14:00:00Z") + index * 6 * 3600 * 1000).toISOString();
  return { start, decisions: 5, executed: 4, denied: 1, held: 0, observed: 0, stale: 0, unknown: 0 };
}

const overview: OverviewView = {
  range: "7d",
  since: "2026-09-12T14:00:00Z",
  until: NOW,
  step_seconds: 21600,
  figures: { decisions: 142, executed: 118, denied: 14, held: 10, observed: 0, stale: 0, unknown: 0 },
  previous: { decisions: 124, executed: 101, denied: 12, held: 11, observed: 0, stale: 0, unknown: 0 },
  series: Array.from({ length: 28 }, (_, index) => bucket(index)),
  pending_approvals: 3,
  lapsed_approvals: 0,
  last_request_at: NOW,
  unsettled: 1,
  awaiting: [],
  monitoring: { sources: 2, reporting: 1, stale: 1, overdue: 0, open_findings: 0 },
  mode: "ENFORCE",
};

const denied: ExecutionSummary = {
  request_ref: "EB-1042",
  external_case: null,
  execution_id: DENIED,
  created_at: NOW,
  changed_at: NOW,
  state: "DENIED",
  state_label: "Denied",
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  target: { canonical_target_id: "c-1", provider_id: "dc01", resource_class: "domain controller", environment: "production" },
  agent: { principal_id: "p-agent", label: "triage-agent-a", kind: "AGENT", number: 1 },
  approval: null,
  reasons: [{ code: "NOT_AUTHORIZED", rule_id: "deny-tier0", sentence: "Deny endpoint.isolate when privilege_class is tier0." }],
  reconcile: { available: false, kind: null, continuation: null },
};

const held: ExecutionSummary = {
  ...denied,
  execution_id: HELD,
  state: "PENDING_APPROVAL",
  state_label: "Held",
  target: { canonical_target_id: "c-2", provider_id: "ws25", resource_class: "workstation", environment: "production" },
  approval: { approval_id: "a-1", state: "PENDING", expires_at: "2026-09-19T14:10:53Z", required_approvers: 1, recorded: 0 },
  reasons: [{ code: "APPROVAL_REQUIRED", rule_id: null, sentence: "A person has to approve it before it can run." }],
};

const page: ExecutionPage = { items: [held, denied], next_cursor: null };

const detail: ExecutionDetail = {
  deliveries: [],
  related_requests: [],
  bundle_id: "b-1",
  policy_readable: true,
  ...denied,
  arguments: [],
  facts: [
    {
      name: "role",
      value: "domain_controller",
      origin: "RESOLVED",
      source_kind: "inventory",
      source_object_id: "dc01",
      source_version: "v7",
      observed_at: "2026-09-01T13:56:11Z",
      valid_until: "2026-09-19T14:06:11Z",
    },
    {
      name: "incident_status",
      value: "OPEN",
      origin: "RESOLVED",
      source_kind: "incident",
      source_object_id: "INC-2041",
      source_version: "v3",
      observed_at: "2026-09-01T14:00:11Z",
      valid_until: "2026-09-19T14:06:11Z",
    },
  ],
  obligations: [],
  limits: [],
  timeline: [
    { at: "2026-09-19T14:02:11.087Z", kind: "transition", state: "ATTEMPTED", actor: denied.agent, sentence: "Request received and the plan frozen." },
    { at: "2026-09-19T14:02:11.118Z", kind: "transition", state: "DENIED", actor: denied.agent, sentence: "Denied: NOT_AUTHORIZED." },
  ],
  checkpoint: [],
  carriers: [],
  dispatch: null,
  observed_effect: null,
  plan_hash: "ab".repeat(32),
  valid_until: "2026-09-19T14:06:11Z",
};

function mount(
  initial = "/",
  who: SessionView = session,
  view: OverviewView = overview,
  extra: Record<string, unknown> = {},
) {
  const calls = serve({
    "/api/console/v1/session": who,
    "/api/console/v1/overview": view,
    "/api/console/v1/executions": page,
    [`/api/console/v1/executions/${DENIED}`]: detail,
    "/api/console/v1/report": REPORT,
    ...extra,
  });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initial] }) });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, calls, client };
}

function section(name: string): HTMLElement {
  const found = screen.getByRole("heading", { name }).closest("section");
  if (found === null) throw new Error(`No section is headed ${name}`);
  return found;
}

function asked(calls: Call[], path: string): number {
  return calls.filter((call) => call.path === path).length;
}

/** Answers the first read with the body and every later one as unavailable. */
function failingAfterOne(body: unknown): () => Response {
  let reads = 0;
  return () => (++reads === 1 ? json(body) : json({ code: "UNAVAILABLE", detail: "Unavailable." }, 503));
}

function at<T>(items: T[], index: number): T {
  const item = items[index];
  if (item === undefined) throw new Error(`No item ${String(index)}`);
  return item;
}

/** An assistant this workspace has turned on, as its settings read answers. */
const ASSISTANT_ON: Settings = {
  enabled: true,
  model: "claude-sonnet-5",
  provider_retention: "Prompts and answers are kept by the model provider for up to 30 days.",
  person_hourly_turns: 20,
  tenant_daily_tokens: 200000,
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Home", () => {
  it("shows the figures, the chart with its text alternative, needs you and recent decisions", async () => {
    const { calls } = mount();
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await screen.findByText("142");
    expect(screen.getByText("118")).toBeInTheDocument();
    expect(screen.getByText("14")).toBeInTheDocument();
    expect(screen.getByText("18 more than the 7 days before")).toBeInTheDocument();
    expect(screen.getByText("83% of decisions")).toBeInTheDocument();
    const chart = screen.getByRole("figure", { name: "Decisions by outcome over the last 7 days" });
    expect(chart).toHaveTextContent(
      "140 in all over the last 7 days, one column every 6 hours: Executed 112, Held 0, Denied 28, Observed 0, Stale 0, Effect unknown 0.",
    );
    expect(screen.getByRole("figure", { name: "Decisions per 6 hours over the last 7 days" })).toHaveTextContent(
      "140 in all across 28 periods, every one of them carrying something, the tallest 5. It ends at 5.",
    );
    // This administrator has no assigned approval, so the card does not say it needs them
    // (#426).
    expect(screen.queryByRole("heading", { name: "Needs you" })).toBeNull();
    const needs = section("Waiting on a person");
    expect(within(needs).getByText("These approvals are assigned to other people.")).toBeInTheDocument();
    expect(within(needs).getByText("3 approvals pending with an approver")).toBeInTheDocument();
    expect(within(needs).getByText("1 dispatch awaiting provider evidence")).toBeInTheDocument();
    expect(within(needs).getByRole("link", { name: "Reconcile" })).toHaveAttribute("href", "/activity?state=UNCERTAIN");
    expect(within(needs).getByText("1 monitoring source or collection quiet")).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: /Recent decisions/ });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(at(rows, 2)).toHaveTextContent("triage-agent-a");
    expect(at(rows, 2)).toHaveTextContent("Denied");
    expect(at(rows, 2)).toHaveTextContent("Deny endpoint.isolate when privilege_class is tier0.");
    expect(at(rows, 2)).not.toHaveTextContent("does not distinguish");
    expect(called(calls, "GET", "/api/console/v1/overview", "?range=7d")).toBe(true);
    expect(called(calls, "GET", "/api/console/v1/executions", "?limit=8")).toBe(true);
  });

  it("opens a row into the drawer with its state in the URL, and closes it on Escape", async () => {
    const user = userEvent.setup();
    const { router } = mount();
    const table = await screen.findByRole("table", { name: /Recent decisions/ });
    await user.click(at(within(table).getAllByRole("button", { name: "Isolate endpoint" }), 1));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ open: DENIED });
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    expect(within(drawer).getByText("Request EB-1042")).toBeInTheDocument();
    expect(within(drawer).getByText("deny-tier0")).not.toBeVisible();
    expect(within(drawer).getByText("Deny endpoint.isolate when privilege_class is tier0.")).toBeInTheDocument();
    expect(within(drawer).getByText("Request denied")).toBeVisible();
    expect(within(drawer).getByText("ExecBound refused this request before dispatch. It does not establish what happened outside this controlled path.")).toBeVisible();
    expect(within(drawer).getByText(/Review the policy and frozen facts/)).toBeVisible();
    expect(within(drawer).getByText("domain_controller")).toBeInTheDocument();
    expect(within(drawer).getByText(/Inventory · \d+ d/)).toBeInTheDocument();
    expect(within(drawer).getByText(/Incident register · /)).toBeInTheDocument();
    const timeline = drawer.querySelector<HTMLElement>("ol.timeline");
    if (timeline === null) throw new Error("No timeline");
    expect(within(timeline).getByText("Request received and the plan frozen.")).toBeVisible();
    expect(within(drawer).getByText("Denied: NOT_AUTHORIZED.")).not.toBeVisible();
    await user.click(within(drawer).getByText("Decision evidence"));
    expect(within(drawer).getByText("deny-tier0")).toBeVisible();
    await user.click(within(drawer).getByText("Timeline evidence"));
    expect(within(drawer).getByText("Denied: NOT_AUTHORIZED.")).toBeVisible();
    // No disabled Explain stands in the drawer's actions (NV17, #678).
    expect(within(drawer).queryByRole("button", { name: /^Explain/ })).toBeNull();
    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(router.state.location.search).toEqual({});
  });

  it("offers one real Explain below the record where there is an assistant, and no disabled one (NV17, #678)", async () => {
    mount(`/?open=${DENIED}`, { ...session, assistant: true }, overview, { "/api/console/v1/assistant/settings": ASSISTANT_ON });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    const explain = await within(drawer).findAllByRole("button", { name: /^Explain/ });
    expect(explain).toHaveLength(1);
    expect(explain[0]).toBeEnabled();
    expect(within(drawer).getByRole("link", { name: "Open in Activity" })).toBeInTheDocument();
  });

  it("returns the focus to the row's button when the drawer closes over a re-rendered list (NV14, #678)", async () => {
    const user = userEvent.setup();
    const { client } = mount();
    const table = await screen.findByRole("table", { name: /Recent decisions/ });
    await user.click(at(within(table).getAllByRole("button", { name: "Isolate endpoint" }), 1));
    await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    // A poll answer draws the list again under the drawer, so the button that opened it is gone.
    await act(async () => {
      client.setQueryData(
        client.getQueryCache().findAll({ queryKey: [{ _id: "listExecutions" }] })[0]?.queryKey ?? [],
        (previous: ExecutionPage | undefined) => (previous === undefined ? previous : { ...previous, items: previous.items.map((item) => ({ ...item })) }),
      );
      await Promise.resolve();
    });
    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(document.querySelector(`[data-record-id="${DENIED}"]`));
    });
  });

  it("reads a lapsed approval in the drawer as lapsed, and an unused one as unused (#678)", async () => {
    const LAPSED = "1a11e04b-0000-4000-8000-000000000003";
    const UNUSED = "2a11e04b-0000-4000-8000-000000000004";
    const approval = { approval_id: "a-9", state: "PENDING", expires_at: "2026-09-19T13:50:00Z", required_approvers: 1, recorded: 0 };
    const lapsed: ExecutionDetail = {
      ...detail,
      ...held,
      execution_id: LAPSED,
      approval: { ...approval, lapsed: true, unused: false },
      reasons: [{ code: "APPROVAL_REQUIRED", rule_id: null, sentence: "A person has to approve it before it can run.", rules: [] }],
    };
    const unused: ExecutionDetail = {
      ...lapsed,
      execution_id: UNUSED,
      approval: { ...approval, state: "APPROVED", lapsed: false, unused: true },
    };
    mount(`/?open=${LAPSED}`, session, overview, {
      [`/api/console/v1/executions/${LAPSED}`]: lapsed,
      [`/api/console/v1/executions/${UNUSED}`]: unused,
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws25" });
    await within(drawer).findByText(/^Lapsed at/);
    expect(within(drawer).getByText(/before a decision\. Nothing ran\./)).toBeInTheDocument();
    expect(within(drawer).getByText("Approval lapsed")).toBeInTheDocument();
    expect(within(drawer).queryByText("Waiting for a person")).toBeNull();
    cleanup();
    mount(`/?open=${UNUSED}`, session, overview, { [`/api/console/v1/executions/${UNUSED}`]: unused });
    const second = await screen.findByRole("dialog", { name: "Isolate endpoint ws25" });
    const approvalSection = (await within(second).findByRole("heading", { name: "Approval" })).closest("section");
    if (approvalSection === null) throw new Error("No approval section");
    expect(approvalSection.textContent).toMatch(/Approved, but not used before .+\. Nothing ran\./);
    expect(within(second).queryByText(/Lapsed at/)).toBeNull();
    expect(within(second).queryByText("Waiting for a person")).toBeNull();
  });

  it("links a denial's rule to that rule only where the server says the reader may open it", async () => {
    const first = { code: "NOT_AUTHORIZED", sentence: "Deny endpoint.isolate when privilege_class is tier0." };
    const ruled: ExecutionDetail = {
      ...detail,
      bundle_id: "acddee11-0000-4000-8000-000000000009",
      policy_readable: true,
      reasons: [{ ...first, rule_id: null, rules: ["deny-tier0"] }],
    };
    mount(`/?open=${DENIED}`, session, overview, { [`/api/console/v1/executions/${DENIED}`]: ruled });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    const link = await within(drawer).findByRole("link", { name: /Rule deny-tier0 in Policy version acddee11/ });
    const href = new URL(link.getAttribute("href") ?? "", "http://console.test");
    expect(href.pathname).toBe("/policy/acddee11-0000-4000-8000-000000000009/rules");
    expect([...href.searchParams.entries()]).toEqual([["rule", "deny-tier0"]]);
    cleanup();
    // This session holds policy.manage somewhere; the server still says no, so no link.
    mount(`/?open=${DENIED}`, session, overview, {
      [`/api/console/v1/executions/${DENIED}`]: { ...ruled, policy_readable: false, reasons: [{ ...first, rule_id: null, rules: ["<b>x</b>"] }] },
    });
    const closed = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    await within(closed).findByText("<b>x</b>");
    expect(within(closed).queryByRole("link", { name: /^Rule / })).toBeNull();
    expect(closed.querySelector("b")).toBeNull();
  });

  it("offers the deciding policy version for a denial no rule names", async () => {
    const cedar: ExecutionDetail = { ...detail, bundle_id: "acddee11-0000-4000-8000-000000000009", policy_readable: true };
    mount(`/?open=${DENIED}`, session, overview, { [`/api/console/v1/executions/${DENIED}`]: cedar });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    expect(await within(drawer).findByRole("link", { name: "Open Policy version acddee11" })).toHaveAttribute(
      "href",
      "/policy/acddee11-0000-4000-8000-000000000009",
    );
  });

  it("restores the drawer from the URL and changes the range through it", async () => {
    const user = userEvent.setup();
    const { router, calls } = mount(`/?open=${DENIED}&range=24h`);
    await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    expect(called(calls, "GET", "/api/console/v1/overview", "?range=24h")).toBe(true);
    await user.keyboard("{Escape}");
    // The page behind a modal drawer is hidden from the accessibility tree until it closes.
    expect(await screen.findByRole("button", { name: "24 hours" })).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("button", { name: "30 days" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ range: "30d" });
    });
    await waitFor(() => {
      expect(called(calls, "GET", "/api/console/v1/overview", "?range=30d")).toBe(true);
    });
  });

  it("shows an approver what awaits them", async () => {
    const approver: SessionView = {
      ...session,
      identity: { principal_id: "p-approver", kind: "HUMAN_APPROVER", label: "B. Chen" },
      access: { managed: false, roles: ["approver"], permissions: ["console.read", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
    };
    const scoped: OverviewView = {
      ...overview,
      monitoring: null,
      awaiting: [
        {
          execution_id: HELD,
          approval_id: "a-1",
          action_label: "Isolate endpoint",
          target: held.target,
          agent: held.agent,
          expires_at: new Date(Date.now() + 4 * 60_000 + 30_000).toISOString(),
        },
      ],
    };
    mount("/", approver, scoped);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await screen.findByRole("heading", { name: "Needs you" });
    const needs = section("Needs you");
    expect(within(needs).getByRole("button", { name: /Isolate endpoint/ })).toHaveTextContent("ws25");
    // Each awaiting approval names its agent, with the handle beside its label (#678).
    expect(within(needs).getByRole("button", { name: /Isolate endpoint/ })).toHaveTextContent("triage-agent-a Agent 1");
    expect(within(needs).getByRole("link", { name: "All approvals" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByText("1 approval awaiting you")).toBeInTheDocument();
    // The deadline in words, with the clock and the zone it falls in.
    expect(within(needs).getByText(/^4 min left, by \d\d:\d\d UTC$/)).toBeInTheDocument();
    expect(screen.queryByText(/monitoring source/)).toBeNull();
  });

  it("counts stale decisions in the tiles, the chart and the legend, so the page reconciles", async () => {
    // #426: stale decisions were counted in the headline and dropped from the legend, so the
    // two disagreed.
    const sparse = Array.from({ length: 28 }, (_, index) => ({
      ...bucket(index),
      decisions: 0,
      executed: 0,
      denied: 0,
      held: 0,
      observed: 0,
      stale: 0,
      unknown: 0,
    }));
    const busy = at(sparse, 9);
    const view: OverviewView = {
      ...overview,
      figures: { decisions: 46, executed: 5, denied: 1, held: 1, observed: 29, stale: 10, unknown: 0 },
      previous: { decisions: 40, executed: 40, denied: 0, held: 0, observed: 0, stale: 0, unknown: 0 },
      series: sparse.map((entry) =>
        entry === busy
          ? { ...entry, decisions: 46, executed: 5, denied: 1, held: 1, observed: 29, stale: 10 }
          : entry,
      ),
    };
    mount("/", session, view);
    await screen.findByText("46");
    const figures = [...document.querySelectorAll<HTMLElement>(".home-figure")].map((node) => node.textContent);
    expect(figures.find((text) => text.startsWith("Stale"))).toContain("10");
    const legend = document.querySelector<HTMLElement>(".legend")?.textContent ?? "";
    expect(legend).toBe("Executed 5Held 1Denied 1Observed 29Stale 10Effect unknown 0");
    // What the legend shows adds to the headline, and the percentage is taken against it.
    expect(5 + 1 + 1 + 29 + 10).toBe(46);
    expect(screen.getByText("11% of decisions")).toBeInTheDocument();
    const chart = screen.getByRole("figure", { name: /Decisions by outcome/ });
    expect(chart).toHaveTextContent("Executed 5, Held 1, Denied 1, Observed 29, Stale 10, Effect unknown 0.");
    expect(chart).toHaveTextContent("All of it is in one of 28 columns,");
  });

  it("says there is no earlier period once, rather than comparing against an empty one", async () => {
    const empty = { decisions: 0, executed: 0, denied: 0, held: 0, observed: 0, stale: 0, unknown: 0 };
    const first: OverviewView = { ...overview, previous: empty };
    mount("/", session, first);
    await screen.findByText("142");
    // Said once, on the headline; the Denied tile gives its share instead (#678).
    expect(screen.getAllByText("No earlier 7 days to compare")).toHaveLength(1);
    expect(screen.queryByText(/The first 7 days/)).toBeNull();
    expect(screen.queryByText(/more than the 7 days before/)).toBeNull();
    const denied = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
      node.textContent.startsWith("Denied"),
    );
    expect(denied?.textContent).toContain("10% of decisions");
  });

  it("says no decisions yet in a workspace that has none", async () => {
    const empty = { decisions: 0, executed: 0, denied: 0, held: 0, observed: 0, stale: 0, unknown: 0 };
    const none: OverviewView = {
      ...overview,
      figures: empty,
      previous: empty,
      series: overview.series.map((entry) => ({ ...entry, ...empty })),
      pending_approvals: 0,
      unsettled: 0,
      monitoring: { sources: 0, reporting: 0, stale: 0, overdue: 0, open_findings: 0 },
      last_request_at: null,
    };
    mount("/", session, none);
    await screen.findByRole("heading", { level: 1, name: "Home" });
    const decisions = await waitFor(() => {
      const found = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
        node.textContent.startsWith("Decisions"),
      );
      if (found === undefined) throw new Error("No Decisions tile yet");
      return found;
    });
    expect(decisions.textContent).toContain("No decisions yet");
    expect(screen.queryByText(/No earlier/)).toBeNull();
    // Nobody has asked yet, which is not the same as everything being settled.
    const waiting = section("Waiting on a person");
    expect(within(waiting).getByText("Nothing yet.")).toBeInTheDocument();
    expect(within(waiting).getByText("No request has reached a decision.")).toBeInTheDocument();
    expect(within(waiting).queryByText(/Every decision is settled/)).toBeNull();
  });

  it("shows an unknown effect as its own open figure, with its list one link away", async () => {
    const view: OverviewView = {
      ...overview,
      figures: { ...overview.figures, unknown: 2 },
      series: overview.series.map((entry, index) => (index === 3 ? { ...entry, unknown: 2 } : entry)),
    };
    mount("/", session, view);
    await screen.findByText("142");
    const tile = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
      node.textContent.startsWith("Effect unknown"),
    );
    if (tile === undefined) throw new Error("No Effect unknown tile");
    expect(tile).toHaveTextContent("Open now");
    expect(within(tile).getByText("2")).toBeInTheDocument();
    expect(within(tile).getByRole("link", { name: "Review" })).toHaveAttribute(
      "href",
      "/activity?state=FAILED_EFFECT_UNKNOWN",
    );
    const unsettled = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
      node.textContent.startsWith("Unsettled"),
    );
    expect(unsettled).toHaveTextContent("Open now");
    // The Held tile still counts what a person can still decide.
    const held = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
      node.textContent.startsWith("Held for a person"),
    );
    expect(held).toHaveTextContent("3");
    expect(document.querySelector(".legend")?.textContent).toContain("Effect unknown 2");
    expect(screen.getByRole("figure", { name: /Decisions by outcome/ })).toHaveTextContent("Effect unknown 2");
  });

  it("reads no outcome with an unknown effect when there is none", async () => {
    mount();
    await screen.findByText("142");
    expect(screen.getByText("No outcome with an unknown effect")).toBeInTheDocument();
  });

  it("says how many approvals lapsed before a decision, apart from those still waiting", async () => {
    mount("/", session, { ...overview, lapsed_approvals: 2 });
    await screen.findByText("142");
    const held = [...document.querySelectorAll<HTMLElement>(".home-figure")].find((node) =>
      node.textContent.startsWith("Held for a person"),
    );
    if (held === undefined) throw new Error("No Held tile");
    // The note opens exactly the set the count holds.
    const note = within(held).getByRole("link", { name: "2 lapsed before a decision · Review" });
    const href = new URL(note.getAttribute("href") ?? "", "http://console.test");
    expect(href.pathname).toBe("/activity");
    expect(Object.fromEntries(href.searchParams)).toEqual({ outcome: "lapsed", state: "PENDING_APPROVAL" });
    const waiting = section("Waiting on a person");
    const lapsedRow = within(waiting).getByText("2 approvals lapsed before a decision").closest("li");
    if (lapsedRow === null) throw new Error("No lapsed row");
    const review = new URL(within(lapsedRow).getByRole("link", { name: "Review" }).getAttribute("href") ?? "", "http://console.test");
    expect(Object.fromEntries(review.searchParams)).toEqual({ outcome: "lapsed", state: "PENDING_APPROVAL" });
    // An administrator's pending row opens Waiting on others, with time left and who can
    // decide each (#678).
    const pending = within(waiting).getByText("3 approvals pending with an approver").closest("li");
    if (pending === null) throw new Error("No pending row");
    expect(within(pending).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/approvals?view=others");
  });

  it.each([
    ["a policy manager", ["policy_manager"], ["console.read", "policy.manage"]],
    ["a viewer", ["viewer"], ["console.read"]],
  ])("opens the held requests on Activity for %s, who cannot use Waiting on others (#678)", async (_who, roles, permissions) => {
    const reader: SessionView = {
      ...session,
      identity: { principal_id: "p-reader", kind: "HUMAN_APPROVER", label: "C. Diaz" },
      access: { managed: true, roles, permissions, workspace_permissions: permissions, space_permissions: {} },
    };
    mount("/", reader, overview);
    await screen.findByText("142");
    const pending = within(section("Waiting on a person")).getByText("3 approvals pending with an approver").closest("li");
    if (pending === null) throw new Error("No pending row");
    expect(within(pending).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/activity?state=PENDING_APPROVAL");
  });

  const quiet = (stale: number, overdue: number): OverviewView => ({
    ...overview,
    monitoring: { sources: 2, reporting: 1, stale, overdue, open_findings: 0 },
  });

  it("counts quiet sources and overdue collections in one row that lands on them (MQ3, #678)", async () => {
    mount("/", session, quiet(1, 1));
    await screen.findByText("142");
    const row = within(section("Waiting on a person")).getByText("2 monitoring sources or collections quiet").closest("li");
    if (row === null) throw new Error("No quiet row");
    expect(within(row).getByRole("link", { name: "Open" })).toHaveAttribute("href", "/monitor?focus=quiet");
  });

  it("shows the quiet row for an overdue collection alone (MQ3, #678)", async () => {
    mount("/", session, quiet(0, 1));
    await screen.findByText("142");
    expect(within(section("Waiting on a person")).getByText("1 monitoring source or collection quiet")).toBeInTheDocument();
  });

  it("shows no quiet row when nothing is quiet (MQ3, #678)", async () => {
    mount("/", session, quiet(0, 0));
    await screen.findByText("142");
    expect(screen.queryByText(/monitoring sources? or collections? quiet/)).toBeNull();
  });

  it("opens the open findings, not the connections, from the findings row", async () => {
    mount("/", session, { ...overview, monitoring: { sources: 2, reporting: 2, stale: 0, overdue: 0, open_findings: 3 } });
    await screen.findByText("142");
    const waiting = section("Waiting on a person");
    const row = within(waiting).getByText("3 open findings").closest("li");
    if (row === null) throw new Error("No findings row");
    expect(within(row).getByRole("link", { name: "Review" })).toHaveAttribute("href", "/monitor?view=findings");
  });

  it("says which day each run of recent decisions belongs to", async () => {
    const yesterday: ExecutionSummary = { ...denied, execution_id: DENIED, created_at: "2026-09-18T22:12:39Z" };
    const twoRows: ExecutionPage = { items: [{ ...held, created_at: NOW }, yesterday], next_cursor: null };
    mount("/", session, overview, { "/api/console/v1/executions": twoRows });
    const table = await screen.findByRole("table", { name: /Recent decisions/ });
    const days = [...table.querySelectorAll(".row-day")].map((node) => node.textContent);
    // One heading per day, not one per row: the list crosses midnight and says so.
    expect(days).toHaveLength(2);
    expect(at(days, 0)).not.toBe(at(days, 1));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
  });

  it("polls the three Home reads on one timer and asks for nothing while the tab is hidden", async () => {
    const approver: SessionView = {
      ...session,
      identity: { principal_id: "p-approver", kind: "HUMAN_APPROVER", label: "B. Chen" },
    };
    const queue: ApprovalList = { view: "pending", items: [], next_cursor: null, server_time: NOW };
    vi.useFakeTimers();
    try {
      const { calls } = mount("/", approver, { ...overview, monitoring: null }, {
        "/api/console/v1/approvals": queue,
      });
      await vi.waitFor(() => {
        expect(asked(calls, "/api/console/v1/approvals")).toBe(1);
        expect(asked(calls, "/api/console/v1/overview")).toBe(1);
        expect(asked(calls, "/api/console/v1/executions")).toBe(1);
      });
      await vi.advanceTimersByTimeAsync(POLL_MS);
      await vi.waitFor(() => {
        expect(asked(calls, "/api/console/v1/approvals")).toBe(2);
      });
      // One tick, one request each: the sidebar's count and the page share one query.
      expect(asked(calls, "/api/console/v1/overview")).toBe(2);
      expect(asked(calls, "/api/console/v1/executions")).toBe(2);
      Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(POLL_MS * 4);
      expect(asked(calls, "/api/console/v1/approvals")).toBe(2);
      expect(asked(calls, "/api/console/v1/overview")).toBe(2);
      expect(asked(calls, "/api/console/v1/executions")).toBe(2);
    } finally {
      Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
      vi.useRealTimers();
    }
  });

  it("keeps the tenant read off the timer, where an administrator's Home leaves it", async () => {
    // #427's second measurement found `tenant` newly in the poll set, ten seconds apart,
    // carrying a name and a mode that change when an administrator changes them.
    const tenant = {
      tenant_id: "t-1",
      name: "Acme SOC",
      mode: "ENFORCE",
      approval_deadline_seconds: 900,
      monitoring: { sources: 2, reporting: 1, stale: 1, overdue: 0, open_findings: 4 },
      stop: null,
      changes: [],
    };
    vi.useFakeTimers();
    try {
      const { calls } = mount("/", session, overview, { "/api/console/v1/tenant": tenant });
      await vi.waitFor(() => {
        expect(asked(calls, "/api/console/v1/overview")).toBe(1);
        expect(asked(calls, "/api/console/v1/tenant")).toBe(1);
      });
      await vi.advanceTimersByTimeAsync(POLL_MS * 6);
      await vi.waitFor(() => {
        expect(asked(calls, "/api/console/v1/overview")).toBeGreaterThan(1);
      });
      expect(asked(calls, "/api/console/v1/tenant")).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the overview and recent decisions through a poll that fails", async () => {
    const { client } = mount("/", session, overview, {
      "/api/console/v1/overview": failingAfterOne(overview),
      "/api/console/v1/executions": failingAfterOne(page),
    });
    await screen.findByText("142");
    await screen.findByRole("table", { name: /Recent decisions/ });
    await act(async () => {
      await client.refetchQueries({ type: "active" });
    });
    expect(await screen.findByText("The overview could not load.")).toBeInTheDocument();
    expect(await screen.findByText("Recent decisions could not load.")).toBeInTheDocument();
    expect(screen.getByText("142")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: /Recent decisions/ })).toBeInTheDocument();
  });

  it("keeps an open record through a poll that fails", async () => {
    const { client } = mount(`/?open=${DENIED}`, session, overview, {
      [`/api/console/v1/executions/${DENIED}`]: failingAfterOne(detail),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint dc01" });
    expect(await within(drawer).findByText("Request EB-1042")).toBeInTheDocument();
    await act(async () => {
      await client.refetchQueries({ queryKey: [{ _id: "readExecution" }] });
    });
    expect(await within(drawer).findByText("This record could not load.")).toBeInTheDocument();
    expect(within(drawer).getByText("Request EB-1042")).toBeInTheDocument();
    expect(within(drawer).getByText("domain_controller")).toBeInTheDocument();
  });

  it("labels one column a day over a week and one every four hours over a day", () => {
    // The server starts a week at the viewer's midnight six days ago (these tests run in UTC).
    const series = (first: string, length: number, hours: number) =>
      Array.from({ length }, (_, index) => ({
        ...bucket(0),
        start: new Date(Date.parse(first) + index * hours * 3600 * 1000).toISOString(),
      }));
    const days = ["2026-09-20", "2026-09-21", "2026-09-22", "2026-09-23", "2026-09-24", "2026-09-25", "2026-09-26"];
    const week = ticks("7d", series("2026-09-20T00:00:00Z", 28, 6));
    expect(week.filter((label) => label !== "")).toEqual(days.map((day) => dayLabel(`${day}T12:00:00Z`)));
    expect(at(week, 1)).toBe("");
    // Today, the seventh day, is labelled where it begins.
    expect(at(week, 24)).toBe(dayLabel("2026-09-26T12:00:00Z"));
    // Across a daylight-saving change the buckets start an hour off midnight; each is dated
    // by its middle, so the labels still name the right days.
    const shifted = ticks("7d", series("2026-09-19T23:00:00Z", 28, 6));
    expect(shifted.filter((label) => label !== "")).toEqual(days.map((day) => dayLabel(`${day}T12:00:00Z`)));
    // A month labels every fifth day counting back from today, so today is always one.
    const month = ticks("30d", series("2026-08-28T00:00:00Z", 30, 24));
    expect(month.filter((label) => label !== "")).toHaveLength(6);
    expect(at(month, 29)).toBe(dayLabel("2026-09-26T12:00:00Z"));
    const day = ticks(
      "24h",
      Array.from({ length: 24 }, (_, index) => ({ ...bucket(0), start: new Date(index * 3600 * 1000).toISOString() })),
    );
    expect(day.filter((label) => label !== "")).toHaveLength(6);
  });
});

describe("Home's line about held requests too few people can decide (#678)", () => {
  const RECORD = {
    approval_id: "9a11e04b-0000-4000-8000-000000000009",
    execution_id: HELD,
    request_ref: "EB-20",
    space_id: "s-1",
    at: NOW,
    state: "PENDING",
  };
  const none: UnroutedApprovals = {
    server_time: NOW,
    pending: 0,
    pending_nobody: 0,
    pending_truncated: false,
    pending_latest: null,
    recent: 0,
    recent_latest: null,
  };
  const unrouted = (changes: Partial<UnroutedApprovals>) => ({
    "/api/console/v1/approval-coverage/unrouted": { ...none, ...changes },
  });

  it("follows an administrator's own awaiting list, before All approvals", async () => {
    const own: OverviewView = {
      ...overview,
      awaiting: [
        {
          execution_id: HELD,
          approval_id: "a-1",
          action_label: "Isolate endpoint",
          target: held.target,
          agent: held.agent,
          expires_at: new Date(Date.now() + 4 * 60_000).toISOString(),
        },
      ],
    };
    mount("/", session, own, unrouted({ pending: 1, pending_nobody: 1, pending_latest: RECORD }));
    const line = await screen.findByText(/No one can approve 1 held request\./);
    const needs = section("Needs you");
    const list = within(needs).getByRole("list");
    const all = within(needs).getByRole("link", { name: "All approvals" });
    expect(list.compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(line.compareDocumentPosition(all) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("qualifies the pending row and drops the note that they are assigned to other people", async () => {
    mount("/", session, overview, unrouted({ pending: 2, pending_nobody: 1, pending_latest: RECORD }));
    await screen.findByText(/2 held requests cannot reach their quorum/);
    const waiting = section("Waiting on a person");
    expect(within(waiting).getByText("3 approvals pending; 2 cannot be approved as things stand")).toBeInTheDocument();
    expect(within(waiting).queryByText("These approvals are assigned to other people.")).toBeNull();
    expect(within(waiting).getByRole("link", { name: "Choose reviewers" })).toHaveAttribute("href", "/approvers#coverage");
  });

  it("reads the pending row as before when every held request can be decided", async () => {
    const { calls } = mount("/", session, overview, unrouted({}));
    await screen.findByText("142");
    await waitFor(() => {
      expect(called(calls, "GET", "/api/console/v1/approval-coverage/unrouted")).toBe(true);
    });
    const waiting = section("Waiting on a person");
    expect(within(waiting).getByText("3 approvals pending with an approver")).toBeInTheDocument();
    expect(within(waiting).getByText("These approvals are assigned to other people.")).toBeInTheDocument();
  });

  it("stops claiming every approval was decided while requests lapsed for want of a reviewer", async () => {
    const quietHome: OverviewView = { ...overview, pending_approvals: 0, unsettled: 0, monitoring: null };
    mount("/", session, quietHome, unrouted({ recent: 3, recent_latest: { ...RECORD, state: "EXPIRED" } }));
    expect(await screen.findByText("Nothing is waiting now.")).toBeInTheDocument();
    expect(screen.getByText(/In the last 7 days, 3 held requests had fewer people who could decide them/)).toBeInTheDocument();
    expect(screen.queryByText("Every decision is settled and every approval decided.")).toBeNull();
  });

  it("keeps the settled empty state with nothing to report", async () => {
    const quietHome: OverviewView = { ...overview, pending_approvals: 0, unsettled: 0, monitoring: null };
    const { calls } = mount("/", session, quietHome, unrouted({}));
    expect(await screen.findByText("Every decision is settled and every approval decided.")).toBeInTheDocument();
    await waitFor(() => {
      expect(called(calls, "GET", "/api/console/v1/approval-coverage/unrouted")).toBe(true);
    });
    expect(screen.queryByText("Nothing is waiting now.")).toBeNull();
  });
});
