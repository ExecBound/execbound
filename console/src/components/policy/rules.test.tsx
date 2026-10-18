// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { client } from "../../api/client.gen";
import type { RulesView } from "../../api/types.gen";
import { Route as RulesRoute } from "../../routes/policy_.$bundleId_.rules";
import { RulesEditor } from "./RulesEditor";

const DRAFT = "22222222-2222-2222-2222-222222222222";
const NEXT = "55555555-5555-5555-5555-555555555555";
const TRIAGE = "66666666-6666-6666-6666-666666666666";
const NIGHT = "77777777-7777-7777-7777-777777777777";
const ACCOUNT = "88888888-8888-8888-8888-888888888888";
const CUSTOMER = "99999999-9999-9999-9999-999999999999";

type Budget = RulesView["budgets"][number];

function budget(overrides: Partial<Budget> = {}): Budget {
  return {
    rule_id: "principal-hourly",
    action: "endpoint.isolate",
    actions: ["endpoint.isolate"],
    scope: "principal",
    group_id: null,
    account_id: null,
    space_id: null,
    qualifier: null,
    window: "1 hour",
    window_seconds: 3600,
    max_targets: 3,
    budget: "autonomous",
    on_exceed: "REQUIRE_APPROVAL",
    editable: true,
    ...overrides,
  };
}

function view(overrides: Partial<RulesView> = {}): RulesView {
  return {
    bundle_id: DRAFT,
    content_hash: "d".repeat(64),
    state: "DRAFT",
    editable: true,
    written_as_rules: true,
    groups: [
      {
        action: "endpoint.isolate",
        label: "Isolate an endpoint",
        rules: [
          {
            id: "allow-workstations",
            action: "endpoint.isolate",
            effect: "ALLOW",
            sentence: "Allow endpoint.isolate when role is workstation.",
            note: null,
            quorum: null,
            when: [{ kind: "fact", name: "role", operator: "is", values: ["workstation"] }],
          },
        ],
      },
    ],
    budgets: [budget()],
    qualifiers: {
      groups: [
        { id: TRIAGE, label: "Tier-1 SOC" },
        { id: NIGHT, label: "Night shift" },
      ],
      accounts: [{ id: ACCOUNT, label: "mock_crowdstrike (88888888)" }],
      spaces: [{ id: CUSTOMER, label: "Customer B" }],
    },
    fields: [
      {
        action: "endpoint.isolate",
        label: "Isolate an endpoint",
        choices: [
          {
            kind: "fact",
            name: "role",
            cedar_type: "String",
            operators: ["is", "is_not", "in"],
            values: ["domain_controller", "server", "workstation"],
            minimum: null,
            maximum: null,
          },
          {
            kind: "fact",
            name: "criticality",
            cedar_type: "Long",
            operators: ["is", "is_not", "in", "at_least", "at_most"],
            values: [],
            minimum: 0,
            maximum: 4,
          },
        ],
      },
    ],
    compiled: {
      cedar_schema: "namespace ExecBound {}",
      authorization_policies: 'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource);',
      approval_policies: "",
    },
    ...overrides,
  };
}

function stub(fetch: (request: Request) => Promise<Response>) {
  client.setConfig({ baseUrl: "http://console.test/", fetch: fetch as typeof globalThis.fetch });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function mount(element: ReactNode, initial = `/policy/${DRAFT}/rules`) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/policy", <p>Policy</p>),
      page("/policy/$bundleId", <p>Bundle</p>),
      page("/policy/$bundleId/rules", element),
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
  client.setConfig({ baseUrl: "/", fetch: undefined });
});

describe("the rules editor", () => {
  it("marks the rule a link named, by value (#678)", async () => {
    mount(<RulesEditor view={view()} focus="allow-workstations" />);
    const item = (await screen.findByText("allow-workstations")).closest("li");
    expect(item).toHaveAttribute("aria-current", "true");
    // The id is matched by value and becomes no element id.
    expect(document.getElementById("allow-workstations")).toBeNull();
    const budgetItem = screen.getByText("principal-hourly").closest("li");
    expect(budgetItem).not.toHaveAttribute("aria-current");
  });

  it("takes a rule id from the address only in the shape a bundle writes one", () => {
    const validate = RulesRoute.options.validateSearch as (search: Record<string, unknown>) => { rule?: string };
    expect(validate({ rule: "deny-tier0" })).toEqual({ rule: "deny-tier0" });
    for (const rule of ["<b>x</b>", "Deny", "a".repeat(81), 7, ""]) {
      expect(validate({ rule }).rule).toBeUndefined();
    }
  });

  it("marks a budget a link named", async () => {
    mount(<RulesEditor view={view()} focus="principal-hourly" />);
    const item = (await screen.findByText("principal-hourly")).closest("li");
    expect(item).toHaveAttribute("aria-current", "true");
  });

  it("marks nothing and throws nothing for an id the bundle does not hold", async () => {
    mount(<RulesEditor view={view()} focus="no-such-rule" />);
    await screen.findByText("allow-workstations");
    expect(document.querySelectorAll('[aria-current="true"]')).toHaveLength(0);
  });

  it("edits an existing rule without dropping its budget or duplicating the rule", async () => {
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(view({ bundle_id: NEXT })); });
    mount(<RulesEditor view={view()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Edit rule" }));
    expect(screen.getByLabelText("Value")).toHaveValue("workstation");
    await userEvent.selectOptions(screen.getByLabelText("Effect"), "DENY");
    await userEvent.click(screen.getByRole("button", { name: "Save rule" }));
    await waitFor(() => { expect(sent).toMatchObject({ rules: [{ id: "allow-workstations", effect: "DENY" }], budgets: [{ rule_id: "principal-hourly", max_targets: 3 }] }); });
    expect((sent as { rules: unknown[] }).rules).toHaveLength(1);
  });

  it("saves readable time units as seconds while preserving the existing rules", async () => {
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(view({ bundle_id: NEXT })); });
    mount(<RulesEditor view={view()} />);
    await userEvent.click(await screen.findByText("Adjust limit"));
    const targets = screen.getByLabelText("Target limit for principal-hourly");
    await userEvent.clear(targets);
    await userEvent.type(targets, "7");
    const period = screen.getByLabelText("Time window for principal-hourly");
    await userEvent.clear(period);
    await userEvent.type(period, "15");
    await userEvent.selectOptions(screen.getByLabelText("Window unit for principal-hourly"), "60");
    await userEvent.click(screen.getByRole("button", { name: "Save limit" }));
    await waitFor(() => { expect(sent).toMatchObject({ rules: [{ id: "allow-workstations", effect: "ALLOW" }], budgets: [{ rule_id: "principal-hourly", window_seconds: 900, max_targets: 7 }] }); });
  });

  it("builds every select from the contract's declared domains", async () => {
    mount(<RulesEditor view={view()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Add a condition" }));
    const name = screen.getByLabelText("Fact or argument");
    expect([...name.querySelectorAll("option")].map((option) => option.textContent)).toEqual([
      "role",
      "criticality",
    ]);
    // A String offers its closed set and nothing else, so an out-of-domain value cannot be sent.
    const value = screen.getByLabelText("Value");
    expect([...value.querySelectorAll("option")].map((option) => option.getAttribute("value"))).toEqual([
      "",
      "domain_controller",
      "server",
      "workstation",
    ]);
    expect([...screen.getByLabelText("Operator").querySelectorAll("option")]).toHaveLength(3);
    // A Long offers the ordered operators and a number bounded by its declared range.
    await userEvent.selectOptions(name, "criticality");
    expect([...screen.getByLabelText("Operator").querySelectorAll("option")]).toHaveLength(5);
    const number = screen.getByLabelText("Value");
    expect(number).toHaveAttribute("type", "number");
    expect(number).toHaveAttribute("min", "0");
    expect(number).toHaveAttribute("max", "4");
  });

  it("adds a rule by stating the whole ruleset, and follows the draft it writes", async () => {
    let sent: unknown;
    stub(async (request) => {
      expect(request.url).toContain(`/policy/${DRAFT}/rules`);
      sent = await request.clone().json();
      return json({ ...view({ bundle_id: NEXT }) });
    });
    const router = mount(<RulesEditor view={view()} />);
    await userEvent.type(await screen.findByLabelText("Rule identifier"), "deny-dc");
    await userEvent.selectOptions(screen.getByLabelText("Effect"), "DENY");
    await userEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    await userEvent.selectOptions(screen.getByLabelText("Value"), "domain_controller");
    await userEvent.click(screen.getByRole("button", { name: "Add the rule" }));
    await waitFor(() => {
      expect(sent).not.toBeUndefined();
    });
    // The rule the draft already had is stated too, so an edit never drops one.
    expect(sent).toEqual({
      rules: [
        {
          id: "allow-workstations",
          action: "endpoint.isolate",
          effect: "ALLOW",
          when: [{ kind: "fact", name: "role", operator: "is", values: ["workstation"] }],
          quorum: null,
          note: null,
        },
        {
          id: "deny-dc",
          action: "endpoint.isolate",
          effect: "DENY",
          when: [{ kind: "fact", name: "role", operator: "is", values: ["domain_controller"] }],
          quorum: null,
          note: null,
        },
      ],
      budgets: [
        {
          rule_id: "principal-hourly",
          action: "endpoint.isolate",
          scope: "principal",
          window_seconds: 3600,
          max_targets: 3,
          budget: "autonomous",
          on_exceed: "REQUIRE_APPROVAL",
        },
      ],
    });
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/policy/${NEXT}/rules`);
    });
  });

  it("asks for a quorum only on a review rule", async () => {
    mount(<RulesEditor view={view()} />);
    expect(screen.queryByLabelText(/Approvers/)).toBeNull();
    await userEvent.selectOptions(await screen.findByLabelText("Effect"), "REVIEW");
    expect(screen.getByLabelText(/Approvers/)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Effect"), "ALLOW");
    expect(screen.queryByLabelText(/Approvers/)).toBeNull();
  });

  it("removes a rule by stating the ruleset without it", async () => {
    let sent: unknown;
    stub(async (request) => {
      sent = await request.clone().json();
      return json(view({ bundle_id: NEXT, groups: [{ action: "endpoint.isolate", label: "x", rules: [] }] }));
    });
    mount(<RulesEditor view={view()} />);
    const rule = (await screen.findByText("allow-workstations")).closest("li");
    await userEvent.click(within(rule ?? document.body).getByRole("button", { name: "Remove" }));
    await waitFor(() => {
      expect(sent).not.toBeUndefined();
    });
    expect((sent as { rules: unknown[] }).rules).toEqual([]);
  });

  it("refuses to edit a draft carrying a budget the form cannot express", async () => {
    const carried = view({
      budgets: [
        budget({ rule_id: "squad-daily", scope: "group", group_id: TRIAGE, qualifier: "Tier-1 SOC" }),
        budget({
          rule_id: "workstations-daily",
          scope: "selector",
          window: "1 day",
          window_seconds: 86400,
          max_targets: 10,
          budget: "total",
          on_exceed: "DENY",
          editable: false,
        }),
      ],
    });
    mount(<RulesEditor view={carried} />);
    // The selector budget is the one named: a group budget is a shape the form states.
    expect(await screen.findByText(/cannot express \(workstations-daily\)/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add the rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    // It is still read, so a person can see what is there before going to the JSON.
    expect(screen.getAllByText(/workstations-daily/).length).toBeGreaterThan(1);
    expect(screen.getByText(/Tier-1 SOC/)).toBeInTheDocument();
  });

  it("adds a group budget from the groups the read offered and restates every qualifier", async () => {
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(view({ bundle_id: NEXT })); });
    const spaced = view({
      budgets: [budget({ rule_id: "customer-hourly", scope: "space", space_id: CUSTOMER, qualifier: "Customer B" })],
    });
    mount(<RulesEditor view={spaced} />);
    // The budget reads with the words for what it is counted for, not its identifier.
    expect(await screen.findByText(/space Customer B/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Agent group")).toBeNull();
    await userEvent.type(screen.getByLabelText("Budget identifier"), "night-daily");
    await userEvent.selectOptions(screen.getByLabelText("Counted for"), "group");
    const groups = screen.getByLabelText("Agent group");
    expect([...groups.querySelectorAll("option")].map((option) => option.textContent)).toEqual([
      "Tier-1 SOC",
      "Night shift",
    ]);
    await userEvent.selectOptions(groups, NIGHT);
    await userEvent.click(screen.getByRole("button", { name: "Add the budget" }));
    await waitFor(() => { expect(sent).not.toBeUndefined(); });
    expect((sent as { budgets: unknown }).budgets).toEqual([
      {
        rule_id: "customer-hourly",
        action: "endpoint.isolate",
        scope: "space",
        space_id: CUSTOMER,
        window_seconds: 3600,
        max_targets: 3,
        budget: "autonomous",
        on_exceed: "REQUIRE_APPROVAL",
      },
      {
        rule_id: "night-daily",
        action: "endpoint.isolate",
        scope: "group",
        group_id: NIGHT,
        window_seconds: 3600,
        max_targets: 3,
        budget: "autonomous",
        on_exceed: "REQUIRE_APPROVAL",
      },
    ]);
  });

  it("offers a qualified scope only where the read offers something to name", async () => {
    mount(<RulesEditor view={view({ qualifiers: { groups: [], accounts: [{ id: ACCOUNT, label: "mock_crowdstrike (88888888)" }], spaces: [] } })} />);
    const scopes = await screen.findByLabelText("Counted for");
    expect([...scopes.querySelectorAll("option")].map((option) => option.getAttribute("value"))).toEqual([
      "principal",
      "tenant",
      "account",
    ]);
    await userEvent.selectOptions(scopes, "account");
    expect(screen.getByLabelText("Connector account")).toHaveValue(ACCOUNT);
  });

  it("changes a budget's group in place, keeping its window and ceiling", async () => {
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(view({ bundle_id: NEXT })); });
    const grouped = view({
      budgets: [budget({ rule_id: "squad", scope: "group", group_id: TRIAGE, qualifier: "Tier-1 SOC" })],
    });
    mount(<RulesEditor view={grouped} />);
    await userEvent.click(await screen.findByText("Adjust limit"));
    const select = screen.getByLabelText("Agent group for squad");
    expect(select).toHaveValue(TRIAGE);
    await userEvent.selectOptions(select, NIGHT);
    await userEvent.click(screen.getByRole("button", { name: "Save limit" }));
    await waitFor(() => { expect(sent).not.toBeUndefined(); });
    expect((sent as { budgets: unknown }).budgets).toEqual([
      {
        rule_id: "squad",
        action: "endpoint.isolate",
        scope: "group",
        group_id: NIGHT,
        window_seconds: 3600,
        max_targets: 3,
        budget: "autonomous",
        on_exceed: "REQUIRE_APPROVAL",
      },
    ]);
  });

  it("locks the draft and names a budget counted for a qualifier the read no longer offers", async () => {
    // The read marks it not editable (#678): every save restating it would be refused, so
    // the whole draft is read and not changed here, as for a budget the form cannot express.
    const stale = view({
      budgets: [
        budget(),
        budget({ rule_id: "gone", scope: "account", account_id: NEXT, qualifier: NEXT, editable: false }),
      ],
    });
    mount(<RulesEditor view={stale} />);
    expect(await screen.findByRole("status")).toHaveTextContent(/cannot express \(gone\)\. It is read here; change it as JSON/);
    for (const name of ["Edit rule", "Remove", "Add the rule", "Add the budget"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    expect(screen.queryByText("Adjust limit")).toBeNull();
    // It is still read, counted for the identifier the read gave it, beside the other budget.
    expect(screen.getByText(new RegExp(`account ${NEXT}`))).toBeInTheDocument();
    expect(screen.getByText(/principal-hourly/)).toBeInTheDocument();
  });

  it("reads but does not change anything that is not a draft", async () => {
    mount(<RulesEditor view={view({ state: "ACTIVE", editable: false })} />);
    expect(await screen.findByText(/Only a draft can be changed/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add the rule" })).toBeNull();
    expect(screen.getByText("Allow isolating an endpoint when the target is a workstation.")).toBeInTheDocument();
    expect(screen.getByText(/permit\(principal/)).toBeInTheDocument();
  });

  it("reads back a signal fact's condition and edits it from the fact's declared domain", async () => {
    // The Defender for Endpoint scenario's REVIEW rule (#478), as the server reads it back over
    // an endpoint-isolation.v2 mapping: tests/test_console_api_rules_signal.py is its pair.
    type RuleView = RulesView["groups"][number]["rules"][number];
    const review: RuleView = {
      id: "isolate-review-unless-compromised",
      action: "endpoint.isolate",
      effect: "REVIEW",
      sentence: "Review endpoint.isolate when compromise is not compromised.",
      note: "Defender's own verdict.",
      quorum: null,
      when: [{ kind: "fact", name: "compromise", operator: "is_not", values: ["compromised"] }],
    };
    const incident: RuleView = {
      id: "isolate-open-incident",
      action: "endpoint.isolate",
      effect: "ALLOW",
      sentence: "Allow endpoint.isolate when incident_status is OPEN.",
      note: null,
      quorum: null,
      when: [{ kind: "fact", name: "incident_status", operator: "is", values: ["OPEN"] }],
    };
    const signal = view({
      groups: [{ action: "endpoint.isolate", label: "Isolate an endpoint", rules: [incident, review] }],
      budgets: [],
      fields: [
        {
          action: "endpoint.isolate",
          label: "Isolate an endpoint",
          choices: [
            {
              kind: "fact",
              name: "incident_status",
              cedar_type: "String",
              operators: ["is", "is_not", "in"],
              values: ["CLOSED", "OPEN"],
              minimum: null,
              maximum: null,
            },
            {
              kind: "fact",
              name: "compromise",
              cedar_type: "String",
              operators: ["is", "is_not", "in"],
              values: ["clean", "compromised", "no_detection", "suspect"],
              minimum: null,
              maximum: null,
            },
          ],
        },
      ],
    });
    let sent: unknown;
    stub(async (request) => { sent = await request.clone().json(); return json(view({ bundle_id: NEXT })); });
    mount(<RulesEditor view={signal} />);
    expect(
      await screen.findByText("Require approval for isolating an endpoint when compromise is not compromised."),
    ).toBeInTheDocument();
    expect(screen.getByText("Note: Defender's own verdict.")).toBeInTheDocument();
    const rule = screen.getByText("isolate-review-unless-compromised").closest("li");
    await userEvent.click(within(rule ?? document.body).getByRole("button", { name: "Edit rule" }));
    // The condition opens as it was written, from the fact's own domain.
    expect(screen.getByLabelText("Fact or argument")).toHaveValue("compromise");
    expect(screen.getByLabelText("Operator")).toHaveValue("is_not");
    const value = screen.getByLabelText("Value");
    expect(value).toHaveValue("compromised");
    expect([...value.querySelectorAll("option")].map((option) => option.getAttribute("value"))).toEqual([
      "",
      "clean",
      "compromised",
      "no_detection",
      "suspect",
    ]);
    // Changed to two approvers unless the EDR reports compromise, and saved as a whole ruleset.
    await userEvent.selectOptions(screen.getByLabelText("Operator"), "in");
    await userEvent.selectOptions(screen.getByLabelText("Value"), ["no_detection", "suspect"]);
    await userEvent.selectOptions(screen.getByLabelText(/Approvers/), "2");
    await userEvent.click(screen.getByRole("button", { name: "Save rule" }));
    await waitFor(() => {
      expect(sent).not.toBeUndefined();
    });
    expect(sent).toEqual({
      rules: [
        {
          id: "isolate-open-incident",
          action: "endpoint.isolate",
          effect: "ALLOW",
          when: [{ kind: "fact", name: "incident_status", operator: "is", values: ["OPEN"] }],
          quorum: null,
          note: null,
        },
        {
          id: "isolate-review-unless-compromised",
          action: "endpoint.isolate",
          effect: "REVIEW",
          when: [{ kind: "fact", name: "compromise", operator: "in", values: ["no_detection", "suspect"] }],
          quorum: 2,
          note: "Defender's own verdict.",
        },
      ],
      budgets: [],
    });
  });

  it("says a bundle written as a document has no rules to read", async () => {
    mount(<RulesEditor view={view({ written_as_rules: false, editable: false, groups: [] })} />);
    expect(await screen.findByText("This bundle was not written as rules.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add the rule" })).toBeNull();
  });
});
