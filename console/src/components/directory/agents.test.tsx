// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useState, type ReactNode } from "react";

import { readAgentOptions } from "../../api/@tanstack/react-query.gen";
import { client } from "../../api/client.gen";
import type { AgentDetail, AgentRow, AgentsPage, TenantLine } from "../../api/types.gen";
import { withEdition } from "../../test/edition";
import { AgentDetailView, type AgentSection } from "./AgentDetail";
import { AgentsList, DEFAULT_SEARCH, parseAgentsSearch, capacityLineText } from "./AgentsList";
import { PLAN_LIMIT_SENTENCE } from "./errors";
import { handle } from "./format";
import { ruleSentence } from "../policy/format";

const MINE = "22222222-2222-2222-2222-222222222222";
const FIRST = "33333333-3333-3333-3333-333333333333";
const SECOND = "44444444-4444-4444-4444-444444444444";
const CONNECTION = "55555555-5555-5555-5555-555555555555";
const LIVE = "66666666-6666-6666-6666-666666666666";
const OLD = "77777777-7777-7777-7777-777777777777";
const BUNDLE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TOKEN = "eb1.00000000-0000-0000-0000-000000000000.88888888-8888-8888-8888-888888888888.secretsecretsecret";

function row(overrides: Partial<AgentRow>): AgentRow {
  return {
    row_id: MINE,
    population: "governed",
    principal_id: MINE,
    agent_id: null,
    name: null,
    number: null,
    active: true,
    dormant: false,
    source: null,
    source_label: "",
    identity_class: null,
    class_label: "",
    enabled: null,
    gone_at: null,
    last_seen: null,
    sponsors: [],
    sponsor_state: null,
    live: 1,
    requests: 0,
    last_request: null,
    last_execution_id: null,
    last_request_ref: null,
    consequential: 0,
    governed_paths: 0,
    lapsed: 0,
    findings: 0,
    ...overrides,
  };
}

const PAGE: AgentsPage = {
  agents: [
    row({
      population: "bound",
      agent_id: FIRST,
      name: "Triage bot",
      source: "entra_agent_id",
      source_label: "Entra",
      identity_class: "agent_identity",
      class_label: "agent identity",
      enabled: true,
      sponsors: [{ kind: "user", ref: "ab12cd34" }],
      sponsor_state: "read",
      requests: 3,
      last_request: "2026-09-19T14:02:11Z",
      consequential: 2,
      governed_paths: 1,
    }),
    row({ row_id: OLD, principal_id: OLD, name: null, active: false, live: 0 }),
    row({
      row_id: SECOND,
      population: "discovered",
      principal_id: null,
      agent_id: SECOND,
      name: "<img src=x onerror=alert(1)>",
      active: null,
      dormant: null,
      source: "entra_agent_id",
      source_label: "Entra",
      identity_class: "service_principal",
      class_label: "classic service principal",
      enabled: false,
      sponsor_state: "not_read",
      last_seen: "2026-09-18T09:00:00Z",
      consequential: 1,
      lapsed: 1,
      findings: 2,
    }),
  ],
  next: "abc",
  active_month: 1,
  month: "2026-09-01T00:00:00Z",
  line: {
    sources: [
      {
        connection_id: CONNECTION,
        label: "Lab tenant",
        kind: "entra_agent_id",
        source_label: "Entra",
        active: true,
        last_sync_at: "2026-09-19T12:00:00Z",
        health_state: "COLLECTING",
        listed: 3,
        consequential: 2,
        bound: 1,
        unestablished: 1,
      },
    ],
    totals: { listed: 3, consequential: 2, bound: 1, unestablished: 1 },
    profiled: true,
    principals: 2,
    principals_total: 3,
    bound: 1,
    agent_limit: null,
    agents_held: 2,
    agents_dormant: 0,
  },
  space_dormant: 0,
};

const GOVERNED: AgentDetail = {
  row_id: MINE,
  kind: "principal",
  agent: { principal_id: MINE, active: true, dormant: false, label: "Triage bot", created_at: "2026-09-10T08:00:00Z", deactivated_at: null },
  binding: null,
  discovered: null,
  credentials: [
    { credential_id: LIVE, issued_at: "2026-09-19T08:00:00Z", expires_at: "2026-09-19T16:00:00Z", revoked_at: null, state: "live", failures: 0 },
    { credential_id: OLD, issued_at: "2026-09-01T08:00:00Z", expires_at: "2026-09-02T08:00:00Z", revoked_at: "2026-09-01T09:00:00Z", state: "revoked", failures: 2 },
  ],
  recent: [
    { execution_id: "99999999-9999-9999-9999-999999999999", action: "endpoint.isolate", label: "Isolate endpoint", canonical_target_id: FIRST, state: "EXECUTED", created_at: "2026-09-19T14:02:11Z", request_ref: "EB-12" },
  ],
  runs: [],
  more_runs: false,
  groups: [{ group_id: CONNECTION, name: "Tier 1 <b>bold</b>" }],
  requests: 1,
  month: "2026-09-01T00:00:00Z",
  bundle: true,
  observe: false,
  limits: [
    { scope: "Principal", budget: "autonomous", actions: "endpoint.isolate", labels: "Isolate endpoint", window: "15 minutes", count: 9, max_targets: 12, on_exceed: "REQUIRE_APPROVAL" },
    { scope: "Account acct-1", budget: "total", actions: "endpoint.isolate", labels: "Isolate endpoint", window: "1 hour", count: null, max_targets: 3, on_exceed: "DENY" },
  ],
  reach: [
    { action: "endpoint.isolate", label: "Isolate endpoint", path_kind: "execbound", path: "ExecBound, this agent's credentials", certainty: "verified", mode: "native", freshness: "last executed 2026-09-19", govern: false, rules: [] },
  ],
  rules_bundle_id: null,
  options: [{ id: SECOND, name: "Synthetic agent 2", detail: "Entra · agent identity" }],
};

// A governed agent with no request yet: the page opens on Connection.
const CONNECTING: AgentDetail = { ...GOVERNED, recent: [] };

const DISCOVERED: AgentDetail = {
  ...GOVERNED,
  row_id: SECOND,
  kind: "discovered",
  agent: null,
  credentials: [],
  recent: [],
  groups: [],
  requests: 0,
  month: null,
  limits: [],
  reach: [
    { action: "identity.disable", label: "Disable identity", path_kind: "grant", path: "grant Directory.ReadWrite.All", certainty: "inferred", mode: "unknown", freshness: "valid until 2026-10-01", govern: true, rules: [] },
  ],
  options: [{ id: MINE, name: "Triage bot", detail: "agent principal" }],
  discovered: {
    agent: {
      agent_id: SECOND,
      platform_ref: "sp-0002",
      identity_class: "agent_identity",
      class_label: "agent identity",
      source_label: "Entra",
      display_name: "Synthetic agent 2",
      enabled: true,
      blueprint_ref: null,
      credential_kinds: ["password"],
      sponsors: [{ kind: "user", ref: "ab12cd34" }],
      sponsor_state: "read",
      first_seen_at: "2026-09-18T09:00:00Z",
      observed_at: "2026-09-19T12:00:00Z",
      gone_at: null,
    },
    findings: [],
    observations: [],
  },
};

// A governed principal bound to a discovered agent (#439): the one shape that
// renders both the Identity/heading badges *and* the Source card in the same page, which is
// where a dormant bound agent could read "Asleep" up top and "is deactivated" in its source
// card at once.
const BOUND: AgentDetail = {
  ...GOVERNED,
  binding: { binding_id: BUNDLE, agent_id: SECOND, principal_id: MINE, bound_by: MINE, bound_at: "2026-09-15T00:00:00Z", bound_by_ref: { principal_id: MINE, kind: "ADMIN", label: null, number: 1 } },
  discovered: DISCOVERED.discovered,
};

function mount(element: ReactNode, initial = "/agents", queryClient = new QueryClient()) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/agents", element),
      page("/agents/$agentId", element),
      page("/activity", <p>Activity</p>),
      page("/policy", <p>Policy</p>),
      page("/policy/$bundleId/rules", <p>Rules</p>),
      page("/monitor", <p>Monitoring</p>),
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

afterEach(() => {
  client.setConfig({ baseUrl: "/", fetch: undefined });
  localStorage.clear();
});

describe("the agents list", () => {
  it("shows the three populations as text, links each row by its id, and carries the month figure", async () => {
    const onSearch = vi.fn();
    mount(<AgentsList data={PAGE} search={DEFAULT_SEARCH} onSearch={onSearch} />);
    await userEvent.click(await screen.findByLabelText("Show discovery details"));
    await userEvent.click(screen.getByText("Discovery coverage and agent capacity"));
    const table = await screen.findByRole("table", { name: /Agents matching the filters/ });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0] ?? table).getByRole("link", { name: "Triage bot" })).toHaveAttribute("href", `/agents/${MINE}`);
    expect(rows[0]).toHaveTextContent("bound");
    expect(rows[0]).toHaveTextContent("Entra · agent identity");
    expect(rows[0]).toHaveTextContent("ab12cd34");
    expect(rows[0]).toHaveTextContent("request 2026-09-19 14:02 UTC");
    expect(within(rows[0] ?? table).getByText("Active")).toHaveClass("badge-allow");
    expect(within(rows[1] ?? table).getByRole("link", { name: handle("Agent", null, OLD) })).toHaveAttribute("href", `/agents/${OLD}`);
    expect(rows[1]).toHaveTextContent("governed only");
    expect(rows[1]).toHaveTextContent("ExecBound only");
    expect(within(rows[1] ?? table).getByText("Deactivated")).toHaveClass("badge-stale");
    // A hostile display name is text.
    expect(within(rows[2] ?? table).getByRole("link", { name: "<img src=x onerror=alert(1)>" })).toHaveAttribute("href", `/agents/${SECOND}`);
    expect(document.querySelector("img")).toBeNull();
    expect(rows[2]).toHaveTextContent("discovered only");
    expect(rows[2]).toHaveTextContent("not read");
    expect(rows[2]).toHaveTextContent("1 · 1 unknown");
    expect(rows[2]).toHaveTextContent("not governed");
    expect(rows[2]).toHaveTextContent("Disabled at the source");
    expect(screen.getByText("Active governed this month").nextSibling).toHaveTextContent("1");
    expect(screen.getByText(/the start of the calendar month in UTC/)).toHaveTextContent("since 2026-09-01");
    expect(screen.getByRole("table", { name: /each monitoring connection lists/ })).toHaveTextContent("Lab tenant · Entra");
    expect(screen.getByRole("link", { name: "Next page" }).getAttribute("href")).toContain("cursor=abc");
    await userEvent.selectOptions(screen.getByLabelText("State"), "deactivated");
    expect(onSearch).toHaveBeenCalledWith({ state: "deactivated", cursor: undefined });
  });

  it("parses a URL's filters to their choices and drops anything else", () => {
    expect(parseAgentsSearch({})).toEqual(DEFAULT_SEARCH);
    expect(parseAgentsSearch({ state: "gone", population: "nope", cursor: "abc", foo: 1 })).toEqual({
      ...DEFAULT_SEARCH,
      state: "gone",
      cursor: "abc",
    });
    expect(parseAgentsSearch({ cursor: "" })).toEqual(DEFAULT_SEARCH);
  });

  it("says when no monitoring connection lists agents", async () => {
    const line = { ...PAGE.line, sources: [], totals: { listed: 0, consequential: 0, bound: 0, unestablished: 0 } };
    // With a filter changed, so the list is a filtered one; an untouched empty list says the
    // Space has no agents yet instead (#678).
    mount(<AgentsList data={{ ...PAGE, agents: [], next: null, line }} search={{ ...DEFAULT_SEARCH, state: "all" }} onSearch={vi.fn()} />);
    expect(await screen.findByRole("status")).toHaveTextContent("No agent matches these filters.");
    await userEvent.click(screen.getByText("Discovery coverage and agent capacity"));
    expect(screen.getByRole("link", { name: "monitoring connection" })).toHaveAttribute("href", "/monitor");
    expect(screen.queryByRole("link", { name: "Next page" })).toBeNull();
  });
});

describe("an empty Space's agents (UX16, #678)", () => {
  it("says the Space has no agents yet, offers Add agent, and shows no filters, disclosure or table", async () => {
    mount(<AgentsList data={{ ...PAGE, agents: [], next: null }} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    expect(await screen.findByText("No agents in this Space yet.")).toBeInTheDocument();
    expect(screen.getByText("Add an agent to give a coding agent or a Tines story its own API key.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add agent" })).toBeInTheDocument();
    expect(screen.getByText(/Deactivated agents are listed under/)).toHaveTextContent("Deactivated agents are listed under State.");
    expect(screen.getByRole("link", { name: "State" }).getAttribute("href")).toContain("state=all");
    expect(document.querySelector('form[aria-label="Filters"]')).toBeNull();
    expect(screen.queryByText("Discovery coverage and agent capacity")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.queryByText("No agent matches these filters.")).toBeNull();
  });

  it("does not call a Space whose agents are all asleep empty: the filters show, and State lists them", async () => {
    // Asleep agents are not active, so the default State hides them; a Space whose every agent
    // went to sleep still has agents, and the State filter is how a person reaches them (#439).
    const onSearch = vi.fn();
    const asleep: AgentsPage = {
      ...PAGE,
      agents: [],
      next: null,
      line: { ...PAGE.line, agents_dormant: 1 },
      space_dormant: 1,
    };
    mount(<AgentsList data={asleep} search={DEFAULT_SEARCH} onSearch={onSearch} />);
    expect(await screen.findByText("No agent matches these filters.")).toBeInTheDocument();
    expect(screen.queryByText("No agents in this Space yet.")).toBeNull();
    const state = screen.getByLabelText("State");
    expect(within(state).getByRole("option", { name: "All" })).toBeInTheDocument();
    await userEvent.selectOptions(state, "all");
    expect(onSearch).toHaveBeenCalledWith({ state: "all", cursor: undefined });
  });

  it("still calls a Space with no agents empty when another Space's agents are asleep", async () => {
    // The tenant line counts the whole workspace's asleep agents; the empty-Space test reads
    // the listed Space's own count, so another Space's sleep leaves this one's empty state.
    const elsewhere: AgentsPage = {
      ...PAGE,
      agents: [],
      next: null,
      line: { ...PAGE.line, agents_dormant: 1 },
      space_dormant: 0,
    };
    mount(<AgentsList data={elsewhere} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    expect(await screen.findByText("No agents in this Space yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add agent" })).toBeInTheDocument();
    expect(document.querySelector('form[aria-label="Filters"]')).toBeNull();
    expect(screen.queryByText("No agent matches these filters.")).toBeNull();
  });

  it("keeps the filtered wording where a filter was changed or a page was turned", async () => {
    mount(<AgentsList data={{ ...PAGE, agents: [], next: null }} search={{ ...DEFAULT_SEARCH, population: "bound" }} onSearch={vi.fn()} />);
    expect(await screen.findByText("No agent matches these filters.")).toBeInTheDocument();
    expect(document.querySelector('form[aria-label="Filters"]')).not.toBeNull();
    cleanup();
    mount(<AgentsList data={{ ...PAGE, agents: [], next: null }} search={{ ...DEFAULT_SEARCH, cursor: "c2" }} onSearch={vi.fn()} />);
    expect(await screen.findByText("No agent matches these filters.")).toBeInTheDocument();
  });
});

describe("the capacity line (#257)", () => {
  function line(overrides: Partial<TenantLine>): TenantLine {
    return { ...PAGE.line, agent_limit: 3, agents_held: 1, agents_dormant: 0, ...overrides };
  }

  it("counts the agents, with no limit shown when the workspace has none", () => {
    expect(capacityLineText(line({ agent_limit: null, agents_held: 5 }))).toBe("Agents: 5.");
  });

  it("shows the count against the limit under it, with no over-limit sentence", async () => {
    const under = line({ agents_held: 1, agent_limit: 3 });
    expect(capacityLineText(under)).toBe("Agents: 1 of 3.");
    mount(<AgentsList data={{ ...PAGE, line: under }} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    expect(await screen.findByText("Agents: 1 of 3.")).toBeInTheDocument();
    expect(screen.queryByText(/reached its agent limit/)).toBeNull();
  });

  it("adds the server refusal's own sentence, word for word (shared from errors.ts), at or over the limit", async () => {
    const atCap = line({ agents_held: 3, agent_limit: 3 });
    expect(capacityLineText(atCap)).toBe(
      "Agents: 3 of 3. This workspace has reached its agent limit. Every agent you have keeps running.",
    );
    expect(PLAN_LIMIT_SENTENCE).toBe("This workspace has reached its agent limit. Every agent you have keeps running.");
    const overCap = line({ agents_held: 5, agent_limit: 3 });
    mount(<AgentsList data={{ ...PAGE, line: overCap }} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    expect(
      await screen.findByText(
        "Agents: 5 of 3. This workspace has reached its agent limit. Every agent you have keeps running.",
      ),
    ).toBeInTheDocument();
  });

  it("says how many agents are asleep and points at the Asleep badge, singular and plural", async () => {
    const one = line({ agents_held: 3, agent_limit: 3, agents_dormant: 1 });
    expect(capacityLineText(one)).toBe(
      "Agents: 3 of 3. This workspace has reached its agent limit. Every agent you have keeps running. " +
        "1 agent is asleep after ninety days without a governed request. Open an agent marked Asleep to reactivate it.",
    );
    const two = line({ agents_held: 2, agent_limit: 3, agents_dormant: 2 });
    expect(capacityLineText(two)).toBe(
      "Agents: 2 of 3. 2 agents are asleep after ninety days without a governed request. Open an agent marked Asleep to reactivate it.",
    );
    mount(<AgentsList data={{ ...PAGE, line: two }} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    expect(
      await screen.findByText(
        "Agents: 2 of 3. 2 agents are asleep after ninety days without a governed request. Open an agent marked Asleep to reactivate it.",
      ),
    ).toBeInTheDocument();
  });
});

describe("the Asleep badge (#439)", () => {
  it("shows Asleep for a dormant row in the list, Deactivated for one turned off by hand, and Active for a live one", async () => {
    const page: AgentsPage = {
      ...PAGE,
      agents: [
        row({ row_id: MINE, principal_id: MINE, name: "Live", active: true, dormant: false }),
        row({ row_id: OLD, principal_id: OLD, name: "Sleeping", active: false, dormant: true }),
        row({ row_id: SECOND, principal_id: SECOND, name: "Hand-off", active: false, dormant: false }),
      ],
    };
    mount(<AgentsList data={page} search={DEFAULT_SEARCH} onSearch={vi.fn()} />);
    const table = await screen.findByRole("table", { name: /Agents matching/ });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(within(rows[0] ?? table).getByText("Active")).toHaveClass("badge-allow");
    expect(within(rows[1] ?? table).getByText("Asleep")).toHaveClass("badge-obs");
    expect(within(rows[1] ?? table).queryByText("Deactivated")).toBeNull();
    expect(within(rows[2] ?? table).getByText("Deactivated")).toHaveClass("badge-stale");
    expect(within(rows[2] ?? table).queryByText("Asleep")).toBeNull();
  });

  it("shows Asleep on the agent detail page (heading and Identity) for a dormant agent", async () => {
    const dormant: AgentDetail = {
      ...GOVERNED,
      agent: {
        principal_id: MINE,
        label: "Triage bot",
        created_at: "2026-09-10T08:00:00Z",
        active: false,
        dormant: true,
        deactivated_at: null,
      },
    };
    mount(<AgentDetailView detail={dormant} />, `/agents/${MINE}`);
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    // The heading badge, and on Overview the Summary and the Identity card.
    expect(screen.getAllByText("Asleep")).toHaveLength(3);
    for (const badge of screen.getAllByText("Asleep")) expect(badge).toHaveClass("badge-obs");
    expect(screen.queryByText("Deactivated")).toBeNull();
    // Waking it uses the same Reactivate control a hand-deactivated agent uses, under
    // Advanced; there is no second control.
    cleanup();
    mount(<AgentDetailView detail={dormant} section="advanced" />, `/agents/${MINE}?section=advanced`);
    expect(await screen.findByRole("button", { name: "Reactivate this agent" })).toBeInTheDocument();
  });

  it("keeps Deactivated (not Asleep) on the agent detail page for one turned off by hand", async () => {
    const deactivated: AgentDetail = {
      ...GOVERNED,
      agent: {
        principal_id: MINE,
        label: "Triage bot",
        created_at: "2026-09-10T08:00:00Z",
        active: false,
        dormant: false,
        deactivated_at: "2026-09-19T15:00:00Z",
      },
    };
    mount(<AgentDetailView detail={deactivated} />, `/agents/${MINE}`);
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    expect(screen.getAllByText("Deactivated")).toHaveLength(3);
    expect(screen.queryByText("Asleep")).toBeNull();
  });
});

describe("the Asleep wording beyond the badges (#439)", () => {
  it("says a bound agent's source card is asleep, not deactivated, when it is dormant", async () => {
    const dormant: AgentDetail = {
      ...BOUND,
      agent: {
        principal_id: MINE,
        label: "Triage bot",
        created_at: "2026-09-10T08:00:00Z",
        active: false,
        dormant: true,
        deactivated_at: null,
      },
    };
    mount(<AgentDetailView detail={dormant} section="advanced" />, `/agents/${MINE}?section=advanced`);
    const heading = await screen.findByRole("heading", { level: 2, name: "What the source lists" });
    const card = heading.closest("section");
    expect(card).toHaveTextContent(
      "The governed principal of this agent is asleep after ninety days without a governed request; the source still lists the agent.",
    );
    expect(card).not.toHaveTextContent("is deactivated");
  });

  it("keeps the source card's deactivated sentence for a bound agent turned off by hand", async () => {
    const deactivated: AgentDetail = {
      ...BOUND,
      agent: {
        principal_id: MINE,
        label: "Triage bot",
        created_at: "2026-09-10T08:00:00Z",
        active: false,
        dormant: false,
        deactivated_at: "2026-09-19T15:00:00Z",
      },
    };
    mount(<AgentDetailView detail={deactivated} section="advanced" />, `/agents/${MINE}?section=advanced`);
    const heading = await screen.findByRole("heading", { level: 2, name: "What the source lists" });
    const card = heading.closest("section");
    expect(card).toHaveTextContent(
      "The governed principal of this agent is deactivated; the source still lists the agent.",
    );
    expect(card).not.toHaveTextContent("is asleep");
  });

  it("says an unbound agent is asleep, not deactivated, in the Binding card", async () => {
    const dormant: AgentDetail = {
      ...GOVERNED,
      agent: {
        principal_id: MINE,
        label: "Triage bot",
        created_at: "2026-09-10T08:00:00Z",
        active: false,
        dormant: true,
        deactivated_at: null,
      },
      options: [],
    };
    mount(<AgentDetailView detail={dormant} section="advanced" />, `/agents/${MINE}?section=advanced`);
    expect(
      await screen.findByText(
        "Not bound. This agent is asleep after ninety days without a governed request; reactivate it first.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/A deactivated agent cannot be bound/)).toBeNull();
  });
});

describe("the agent detail", () => {
  it("restores each agent's own saved host when switching agent details", async () => {
    localStorage.setItem(`execbound.agent-host.${MINE}`, "cursor.json");
    localStorage.setItem(`execbound.agent-host.${SECOND}`, "mcp");
    function SwitchAgent() {
      const [other, setOther] = useState(false);
      const detail = other ? { ...GOVERNED, row_id: SECOND, agent: { ...GOVERNED.agent, principal_id: SECOND, active: true, dormant: false, label: "Second agent", created_at: null, deactivated_at: null } } : GOVERNED;
      return <><button onClick={() => { setOther(true); }}>Open second agent</button><AgentDetailView detail={detail} section="connection" /></>;
    }
    mount(<SwitchAgent />, `/agents/${MINE}`);
    expect(await screen.findByLabelText("Agent host")).toHaveValue("cursor.json");
    await userEvent.click(screen.getByRole("button", { name: "Open second agent" }));
    expect(screen.getByLabelText("Agent host")).toHaveValue("mcp");
  });

  it("makes conditional Permissions and resource scope explicit without treating vendor reach as enforcement", async () => {
    const path = GOVERNED.reach[0];
    if (path === undefined) throw new Error("The fixture must contain an ExecBound path");
    const detail = {
      ...BOUND,
      space: { space_id: FIRST, name: "Security" },
      permissions_bundle_id: BUNDLE,
      permissions_inherited: true,
      rules_bundle_id: BUNDLE,
      reach: [
        { ...path, resource_scope: ["endpoint · mock_crowdstrike · account synthetic-account"], rules: [{ id: "production-review", effect: "review", description: "Review endpoint.isolate when environment is production." }] },
        ...DISCOVERED.reach,
      ],
    };
    mount(<AgentDetailView detail={detail} section="permissions" />, `/agents/${MINE}?section=permissions`);
    const permissions = await screen.findByRole("region", { name: "Permissions" });
    expect(within(permissions).getByText("Security")).toBeInTheDocument();
    expect(within(permissions).getByText(/Shared policy selected by this Space/)).toBeInTheDocument();
    // The rule reads as a sentence beside its effect as a word (AK8).
    expect(within(permissions).getByText(ruleSentence("Review endpoint.isolate when environment is production."))).toBeInTheDocument();
    expect(within(permissions).getByText("Review")).toHaveClass("badge-hold");
    expect(within(permissions).getByText(/account synthetic-account/)).toBeInTheDocument();
    expect(within(permissions).getByText(/Each request is evaluated/)).toBeInTheDocument();
    expect(within(permissions).getByRole("heading", { name: "Observed vendor reach" })).toBeInTheDocument();
    expect(within(permissions).getByText(/does not establish an enforced path/)).toBeInTheDocument();
    // The section strip's own link to it, the current one.
    const strip = screen.getByRole("navigation", { name: "Agent sections" });
    expect(within(strip).getByRole("link", { name: "Permissions" })).toHaveAttribute("href", `/agents/${MINE}?section=permissions`);
    expect(within(strip).getByRole("link", { name: "Permissions" })).toHaveAttribute("aria-current", "page");
  });

  it("shows identity, binding, credentials, reach, activity and limits as meters for a governed agent", async () => {
    const at = (section: AgentSection) => {
      cleanup();
      mount(<AgentDetailView detail={GOVERNED} section={section} />, `/agents/${MINE}?section=${section}`);
    };
    // Each card in the section the page now keeps it in, and only there.
    const where: [AgentSection, string[]][] = [
      ["overview", ["Summary", "Identity", "This month"]],
      ["connection", ["Connect this agent", "API keys"]],
      ["permissions", ["Permissions", "Limits"]],
      ["activity", ["Recent activity"]],
      ["advanced", ["Binding", "Deactivate"]],
    ];
    for (const [section, cards] of where) {
      at(section);
      expect(await screen.findByRole("heading", { level: 1, name: "Triage bot" })).toBeInTheDocument();
      for (const card of cards) {
        expect(screen.getByRole("heading", { level: 2, name: card })).toBeInTheDocument();
      }
      for (const [other, elsewhere] of where) {
        if (other === section) continue;
        for (const card of elsewhere) expect(screen.queryByRole("heading", { level: 2, name: card })).toBeNull();
      }
    }
    at("overview");
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    expect(screen.getByText("Tier 1 <b>bold</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    at("permissions");
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    const meter = screen.getByRole("meter", { name: "Principal · autonomous · Isolate endpoint" });
    expect(meter).toHaveAttribute("aria-valuenow", "9");
    expect(meter).toHaveAttribute("aria-valuemax", "12");
    expect(screen.getByText("9 targets of 12 in the rolling window of 15 minutes; when exceeded, needs approval")).toBeInTheDocument();
    expect(screen.getByText("counted per request")).toBeInTheDocument();
    expect(screen.getByText("verified")).toHaveClass("badge-allow");
    at("connection");
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    expect(screen.getByRole("button", { name: `Revoke ${LIVE.slice(0, 8)}` })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: `Revoke ${OLD.slice(0, 8)}` })).toBeNull();
    expect(screen.getByRole("button", { name: "Issue API key" })).toBeInTheDocument();
    at("advanced");
    await screen.findByRole("heading", { level: 1, name: "Triage bot" });
    expect(screen.getByRole("button", { name: "Bind" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Deactivate this agent" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Govern this agent" })).toBeNull();
    at("activity");
    const activity = (await screen.findByRole("heading", { level: 2, name: "Recent activity" })).closest("section");
    if (activity === null) throw new Error("No Recent activity card");
    expect(within(activity).getByText("executed")).toHaveClass("badge-allow");
  });

  it("names the rules a bundle written as rules holds for each path, and links each to them", async () => {
    const detail: AgentDetail = {
      ...GOVERNED,
      rules_bundle_id: BUNDLE,
      reach: [
        { action: "endpoint.isolate", label: "Isolate endpoint", path_kind: "execbound", path: "ExecBound, this agent's credentials", certainty: "verified", mode: "native", freshness: "last executed 2026-09-19", govern: false, rules: [{ id: "isolate-workstation-open-critical", effect: "allow" }, { id: "isolate-never-domain-controller", effect: "deny" }] },
        { action: "endpoint.lift_isolation", label: "Lift isolation", path_kind: "execbound", path: "ExecBound, this agent's credentials", certainty: "inferred", mode: "native", freshness: "from the active bundle", govern: false, rules: [] },
        { action: "identity.disable", label: "Disable identity", path_kind: "grant", path: "grant Directory.ReadWrite.All", certainty: "inferred", mode: "unknown", freshness: "valid until 2026-10-01", govern: true, rules: [] },
      ],
    };
    mount(<AgentDetailView detail={detail} section="permissions" />, `/agents/${MINE}?section=permissions`);
    const table = await screen.findByRole("table", { name: /Rules are as they read for the action/ });
    const rows = within(table).getAllByRole("row");
    expect(within(rows[0] ?? table).getByRole("columnheader", { name: "Rules" })).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent("allow rule · conditions unavailable isolate-workstation-open-critical");
    expect(rows[1]).toHaveTextContent("deny rule · conditions unavailable isolate-never-domain-controller");
    for (const name of ["isolate-workstation-open-critical", "isolate-never-domain-controller"]) {
      expect(within(table).getByRole("link", { name })).toHaveAttribute("href", `/policy/${BUNDLE}/rules`);
    }
    // A governed path the rules never name says so; a grant row has no rule to name at all.
    expect(rows[2]).toHaveTextContent("no rule names this action");
    const external = screen.getByRole("table", { name: /External vendor authority/ });
    expect(external).not.toHaveTextContent("no rule names this action");
    expect(external).toHaveTextContent("Directory.ReadWrite.All");
  });

  it("shows no rule column at all for a bundle written as a document", async () => {
    const document = {
      authorization_policies: 'forbid(principal, action, resource) when { resource.criticality == 4 };',
      approval_policies: "", complete: false,
      rules: [{ id: "authorization:policy0", effect: "Deny", description: 'any agent; any action; any target; when target.criticality equals 4.' },
        { id: "authorization:policy1", effect: "Deny", description: null }],
    };
    mount(<AgentDetailView detail={{ ...GOVERNED, policy_document: document }} section="permissions" />, `/agents/${MINE}?section=permissions`);
    const table = await screen.findByRole("table", { name: /Actions the active bundle governs/ });
    expect(within(table).queryByRole("columnheader", { name: "Rules" })).toBeNull();
    expect(table).not.toHaveTextContent("no rule names this action");
    expect(table.textContent).not.toContain("Rules are as they read");
    const conditions = screen.getByRole("region", { name: "Policy conditions" });
    expect(conditions).toHaveTextContent("target.criticality equals 4");
    expect(conditions).toHaveTextContent("Some policy syntax cannot be summarized");
    expect(conditions).toHaveTextContent("Read the exact document for this condition");
    await userEvent.click(within(conditions).getByText("Exact policy documents"));
    expect(within(conditions).getByText(document.authorization_policies)).toBeVisible();
  });

  it("offers a deactivated agent no credential form, no binding and a Reactivate", async () => {
    const detail: AgentDetail = {
      ...GOVERNED,
      agent: {
        ...GOVERNED.agent,
        principal_id: MINE,
        active: false,
        dormant: false,
        label: null,
        created_at: null,
        deactivated_at: "2026-09-19T15:00:00Z",
      },
      options: [],
    };
    mount(<AgentDetailView detail={detail} section="advanced" />, `/agents/${MINE}?section=advanced`);
    expect(await screen.findByRole("heading", { level: 1, name: handle("Agent", null, MINE) })).toBeInTheDocument();
    // A deactivated agent has no Connection section at all.
    expect(within(screen.getByRole("navigation", { name: "Agent sections" })).queryByRole("link", { name: "Connection" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Issue API key" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Bind" })).toBeNull();
    expect(screen.getByText("Not bound. A deactivated agent cannot be bound; reactivate it first.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reactivate this agent" })).toBeInTheDocument();
    expect(screen.getByText(/created before labels/)).toBeInTheDocument();
  });

  it("offers a discovered agent Govern this agent and a Bind, and a gone one neither", async () => {
    mount(<AgentDetailView detail={DISCOVERED} />, `/agents/${SECOND}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Synthetic agent 2" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Govern this agent" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bind" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "What the source lists" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { level: 2, name: "API keys" })).toBeNull();
    expect(screen.getByText("sp-0002")).toHaveClass("mono");
    // A discovered agent has Overview, Permissions and Activity, and no Connection or Advanced.
    const strip = screen.getByRole("navigation", { name: "Agent sections" });
    expect(within(strip).getAllByRole("link").map((link) => link.textContent)).toEqual(["Overview", "Permissions", "Activity"]);
    // The way back to Monitoring opens this agent's own page there (MQ9, #678).
    expect(screen.getByRole("link", { name: "This agent's Monitoring page" })).toHaveAttribute("href", `/monitor/agents/${SECOND}`);
    cleanup();
    mount(<AgentDetailView detail={DISCOVERED} section="activity" />, `/agents/${SECOND}?section=activity`);
    expect(await screen.findByRole("heading", { level: 2, name: "Observations and findings" })).toBeInTheDocument();
    cleanup();
    mount(<AgentDetailView detail={DISCOVERED} section="permissions" />, `/agents/${SECOND}?section=permissions`);
    expect(await screen.findByRole("link", { name: "Govern this action" })).toHaveAttribute("href", "/policy");
  });

  it("offers a gone agent nothing", async () => {
    const found = DISCOVERED.discovered;
    if (found === null) throw new Error("fixture");
    const detail: AgentDetail = { ...DISCOVERED, discovered: { ...found, agent: { ...found.agent, gone_at: "2026-09-19T12:00:00Z" } } };
    mount(<AgentDetailView detail={detail} />, `/agents/${SECOND}`);
    expect(await screen.findByText("This agent is gone from its source, so it cannot be bound or governed.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Govern this agent" })).toBeNull();
    expect(screen.getByText("Gone from the source")).toHaveClass("badge-stale");
  });

  it("links each recent request to its record in Activity (UX13, #678)", async () => {
    mount(<AgentDetailView detail={GOVERNED} section="activity" />, `/agents/${MINE}?section=activity`);
    const activity = (await screen.findByRole("heading", { level: 2, name: "Recent activity" })).closest("section");
    if (activity === null) throw new Error("No Recent activity card");
    expect(within(activity).getByRole("link", { name: "Isolate endpoint" })).toHaveAttribute(
      "href",
      "/activity?open=99999999-9999-9999-9999-999999999999",
    );
  });

  it("issues an API key that never expires, warning what that means first", async () => {
    const fetch = vi.fn((input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const body = url.endsWith("/credentials/issue")
        ? { token: TOKEN, credential_id: LIVE, principal_id: MINE, kind: "AGENT", expires_at: "9999-12-31T00:00:00Z" }
        : url.endsWith("/connection")
          ? { origin: "http://console.test", recipes: {}, workstation: null, operation_ref: null, samples_state: "absent" }
          : GOVERNED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
      );
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    mount(<AgentDetailView detail={CONNECTING} />, `/agents/${MINE}`, new QueryClient());
    const lifetime = await screen.findByLabelText("API key expires after");
    expect(within(lifetime).getByRole("option", { name: "Never" })).toBeInTheDocument();
    expect(screen.queryByText(/stays valid until you revoke it/)).toBeNull();
    await userEvent.selectOptions(lifetime, "never");
    expect(screen.getByText(/stays valid until you revoke it/)).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Issue another API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Copy the API key now" });
    expect(dialog).toHaveTextContent("never expires");
    const request = fetch.mock.calls
      .map((call) => call[0])
      .find((input) => input instanceof Request && input.url.endsWith("/credentials/issue"));
    expect(request).toBeInstanceOf(Request);
    if (request instanceof Request) {
      expect(await request.clone().text()).toBe(JSON.stringify({ lifetime: "never" }));
    }
  });

  it("issues a credential that is shown once and then is nowhere", async () => {
    const fetch = vi.fn((input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const body = url.endsWith("/credentials/issue")
        ? { token: TOKEN, credential_id: LIVE, principal_id: MINE, kind: "AGENT", expires_at: "2026-09-19T22:00:00Z" }
        : url.endsWith("/connection")
          ? { origin: "http://console.test", recipes: { "claude_code.sh": "claude mcp add" }, workstation: null, operation_ref: null, samples_state: "absent" }
          : GOVERNED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
      );
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    const queryClient = new QueryClient();
    mount(<AgentDetailView detail={CONNECTING} />, `/agents/${MINE}`, queryClient);
    await userEvent.selectOptions(await screen.findByLabelText("API key expires after"), "24");
    await userEvent.click(screen.getByRole("button", { name: "Issue another API key" }));
    const field = await screen.findByLabelText("API key (copy it now)");
    expect(field).toHaveValue(TOKEN);
    // The page also reads whether this deployment has an assistant (#330), so the issue is
    // found by what it is rather than by being the first request the page made.
    const request = fetch.mock.calls
      .map((call) => call[0])
      .find((input) => input instanceof Request && input.url.endsWith("/credentials/issue"));
    expect(request).toBeInstanceOf(Request);
    if (request instanceof Request) {
      expect(request.method).toBe("POST");
      expect(await request.clone().text()).toBe(JSON.stringify({ lifetime: "24" }));
    }
    await userEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(document.body.innerHTML).not.toContain(TOKEN);
    await waitFor(() => {
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    });
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state))).not.toContain(TOKEN);
  });

  it("names the whole request in its example: the server's operation, the hostname and the incident", async () => {
    const fetch = vi.fn((input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const body = url.endsWith("/connection")
        ? {
            origin: "http://console.test",
            recipes: { "claude_code.sh": "claude mcp add" },
            workstation: { kind: "hostname", value: "ws-dev-01.sample.invalid", incident_id: "22222222-0000-4000-8000-000000000001" },
            operation_ref: "op.from-the-server",
            samples_state: "removable",
          }
        : GOVERNED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
      );
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    mount(<AgentDetailView detail={CONNECTING} />, `/agents/${MINE}`);
    expect(await screen.findByText(/^Sample target test/)).toHaveTextContent(
      "Sample target test: ask your agent to call execute with operation_ref op.from-the-server, target hostname ws-dev-01.sample.invalid and claimed_context.incident_id 22222222-0000-4000-8000-000000000001. This can change the protected mock endpoint.",
    );
  });

  it("names the target and incident alone where the server names no operation", async () => {
    const fetch = vi.fn((input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const body = url.endsWith("/connection")
        ? {
            origin: "http://console.test",
            recipes: { "claude_code.sh": "claude mcp add" },
            workstation: { kind: "hostname", value: "ws-dev-01.sample.invalid", incident_id: "22222222-0000-4000-8000-000000000001" },
            operation_ref: null,
            samples_state: "removable",
          }
        : GOVERNED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
      );
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    mount(<AgentDetailView detail={CONNECTING} />, `/agents/${MINE}`);
    expect(await screen.findByText(/^Sample target test/)).toHaveTextContent(
      "Sample target test: ask your agent to isolate ws-dev-01.sample.invalid for incident 22222222-0000-4000-8000-000000000001.",
    );
  });

  it("names an edition's workstation where core names none (#496)", async () => {
    const fetch = vi.fn((input: Request | string | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const body = url.endsWith("/connection")
        ? { origin: "http://console.test", recipes: { "claude_code.sh": "claude mcp add" }, workstation: null, operation_ref: null, samples_state: "absent" }
        : GOVERNED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } }),
      );
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    mount(withEdition(<AgentDetailView detail={CONNECTING} />, { FixtureHint: () => <p>Edition workstation</p> }), `/agents/${MINE}`);
    expect(await screen.findByText("Edition workstation")).toBeInTheDocument();
    expect(screen.queryByText(/^Sample target test/)).toBeNull();
    expect(fetch.mock.calls.some(([input]) => String(input instanceof Request ? input.url : input).endsWith("/welcome"))).toBe(false);
  });

  describe("where an edition's workstation stays out (#496)", () => {
    const EDITION = { FixtureHint: () => <p>Edition workstation</p> };

    function answer(body: unknown, status = 200): Promise<Response> {
      return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
    }

    /** The agent's page in an edition that names a workstation, with `/connection` answered by `connection`. */
    function mountWithHint(connection: () => Promise<Response>) {
      const fetch = vi.fn((input: Request | string | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        return url.endsWith("/connection") ? connection() : answer(GOVERNED);
      });
      client.setConfig({ baseUrl: "http://console.test/", fetch });
      const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      mount(withEdition(<AgentDetailView detail={CONNECTING} />, EDITION), `/agents/${MINE}`, queryClient);
    }

    it("is absent where core names its own sample workstation", async () => {
      mountWithHint(() =>
        answer({
          origin: "http://console.test",
          recipes: { "claude_code.sh": "claude mcp add" },
          workstation: { kind: "hostname", value: "ws-dev-01.sample.invalid", incident_id: "22222222-0000-4000-8000-000000000001" },
          operation_ref: "op.from-the-server",
          samples_state: "removable",
        }),
      );
      expect(await screen.findByText(/^Sample target test/)).toBeInTheDocument();
      expect(screen.queryByText("Edition workstation")).toBeNull();
    });

    it("is absent while core's answer is still on its way", async () => {
      mountWithHint(() => new Promise<Response>(() => undefined));
      expect(await screen.findByText("Loading gateway configuration…")).toBeInTheDocument();
      expect(screen.queryByText("Edition workstation")).toBeNull();
    });

    it("is absent where core's answer failed", async () => {
      mountWithHint(() => answer({ code: "UNAVAILABLE", detail: "Unavailable." }, 503));
      expect(await screen.findByText("ExecBound is unavailable; try again shortly.")).toBeInTheDocument();
      expect(screen.queryByText("Edition workstation")).toBeNull();
    });
  });
});

describe("naming an unlabelled agent from its heading (#678)", () => {
  const UNLABELLED: AgentDetail = { ...GOVERNED, agent: { ...GOVERNED.agent, principal_id: MINE, label: null, number: 4 } as AgentDetail["agent"] };

  /** The page as the route reads it: the query holds the detail, so the server's answer is
   * what replaces it, never the click. */
  function Page() {
    const query = useQuery(readAgentOptions({ path: { row_id: MINE } }));
    return query.data === undefined ? <p>Loading</p> : <AgentDetailView detail={query.data} />;
  }

  function answering(answer: (label: string) => Response | Promise<Response>) {
    let posted: string | null = null;
    const fetch = vi.fn(async (input: Request | string | URL) => {
      const request = input instanceof Request ? input : new Request(String(input));
      if (request.method === "POST" && request.url.endsWith(`/agents/${MINE}/label`)) {
        posted = (JSON.parse(await request.clone().text()) as { label: string }).label;
        return answer(posted);
      }
      if (request.url.includes(`/agents/${MINE}`)) return new Response(JSON.stringify(UNLABELLED), { status: 200, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ code: "NOT_FOUND", detail: "Not found" }), { status: 404, headers: { "content-type": "application/json" } });
    });
    client.setConfig({ baseUrl: "http://console.test/", fetch });
    return { posted: () => posted };
  }

  it("offers the prompt under the heading of an unlabelled agent and not of a labelled one", async () => {
    mount(<AgentDetailView detail={UNLABELLED} />, `/agents/${MINE}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Agent 4" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Name this agent" })).toBeInTheDocument();
    expect(screen.getByText("Name this agent so teammates recognise it in approvals and Activity.")).toBeInTheDocument();
    expect(screen.getByLabelText("Agent name")).toHaveAttribute("maxlength", "80");
  });

  it("saves the trimmed name and goes only once the server answers, and the Identity card follows", async () => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const sent = answering(async (label) => {
      await held;
      return new Response(JSON.stringify({ ...UNLABELLED, agent: { ...UNLABELLED.agent, label } }), { status: 200, headers: { "content-type": "application/json" } });
    });
    mount(<Page />, `/agents/${MINE}`);
    await userEvent.type(await screen.findByLabelText("Agent name"), "  triage-bot  ");
    await userEvent.click(screen.getByRole("button", { name: "Save name" }));
    await waitFor(() => {
      expect(sent.posted()).toBe("triage-bot");
    });
    // Nothing optimistic: until the answer the prompt and the old heading stay.
    expect(screen.getByRole("form", { name: "Name this agent" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Agent 4" })).toBeInTheDocument();
    release();
    expect(await screen.findByRole("heading", { level: 1, name: "triage-bot" })).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Name this agent" })).toBeNull();
    expect(screen.getByLabelText("Label (1 to 80 characters)")).toHaveValue("triage-bot");
  });

  it("shows the existing refusal for a name the server refuses, and keeps the field", async () => {
    answering(() => new Response(JSON.stringify({ code: "INVALID_BODY", detail: "x", fields: ["label"] }), { status: 400, headers: { "content-type": "application/json" } }));
    mount(<Page />, `/agents/${MINE}`);
    await userEvent.type(await screen.findByLabelText("Agent name"), "<b>bot</b>");
    await userEvent.click(screen.getByRole("button", { name: "Save name" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByLabelText("Agent name")).toHaveValue("<b>bot</b>");
    expect(screen.getByRole("heading", { level: 1, name: "Agent 4" })).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
  });
});
