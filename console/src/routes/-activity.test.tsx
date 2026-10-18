// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ExecutionDetail, ExecutionPage, ExecutionSummary, SessionView, Settings } from "../api/types.gen";
import { NO_SERVICE } from "../lib/session";
import { clearToasts } from "../lib/toast";
import { dateTime } from "../lib/words";
import { activitySearch } from "../lib/activity-search";
import { filters } from "./activity";
import { routeTree } from "../routeTree.gen";
import { called, calledWith, json, serve } from "../test/api";

const COMMITTED = "50c680b9-0000-4000-8000-000000000003";
const DENIED = "7c21e04b-0000-4000-8000-000000000001";
const LATER = "9a11e04b-0000-4000-8000-000000000002";
const APPROVAL = "a9910000-0000-4000-8000-000000000004";
const READING = "11111111-1111-4111-8111-111111111111";
const DECIDING = "22222222-2222-4222-8222-222222222222";
const NOW = "2026-09-19T14:02:11Z";
const LIST = "/api/console/v1/executions";
const RECONCILE = `/api/console/v1/executions/${COMMITTED}/reconcile`;

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

const committed: ExecutionSummary = {
  request_ref: "EB-1042",
  external_case: null,
  execution_id: COMMITTED,
  created_at: NOW,
  changed_at: NOW,
  state: "DISPATCH_COMMITTED",
  state_label: "Committed",
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  target: { canonical_target_id: "c-1", provider_id: "ws07", resource_class: "workstation", environment: "development" },
  agent: { principal_id: "p-agent", label: "triage-agent-b", kind: "AGENT", number: 2 },
  approval: null,
  reasons: [],
  reconcile: { available: true, kind: "provider", continuation: null },
};

const denied: ExecutionSummary = {
  ...committed,
  execution_id: DENIED,
  state: "DENIED",
  state_label: "Denied",
  target: { canonical_target_id: "c-2", provider_id: "dc01", resource_class: "domain controller", environment: "production" },
  reasons: [{ code: "NOT_AUTHORIZED", rule_id: "deny-tier0", sentence: "Deny endpoint.isolate when privilege_class is tier0." }],
  reconcile: { available: false, kind: null, continuation: null },
};

const later: ExecutionSummary = { ...denied, execution_id: LATER };

const detail: ExecutionDetail = {
  deliveries: [],
  related_requests: [],
  bundle_id: "b-1",
  policy_readable: true,
  ...committed,
  reconcile: { available: true, kind: "provider", continuation: "cont-1" },
  arguments: [],
  facts: [],
  obligations: [],
  limits: [],
  timeline: [
    { at: "2026-09-19T14:02:11.087Z", kind: "transition", state: "ATTEMPTED", actor: committed.agent, sentence: "Request received and the plan frozen." },
    { at: "2026-09-19T14:02:11.118Z", kind: "transition", state: "DISPATCH_COMMITTED", actor: committed.agent, sentence: "Dispatch committed." },
  ],
  checkpoint: [],
  carriers: [],
  dispatch: null,
  observed_effect: null,
  plan_hash: "ab".repeat(32),
  valid_until: "2026-09-19T14:06:11Z",
};

/** The open record, held for an approval in the given state. */
function withApproval(state: string): ExecutionDetail {
  return {
    ...detail,
    state: "PENDING_APPROVAL",
    state_label: "Waiting for approval",
    reconcile: { available: false, kind: null, continuation: null },
    approval: { approval_id: APPROVAL, state, expires_at: "2026-09-19T14:17:11Z", required_approvers: 1, recorded: 0 },
  };
}

function pages(request: Request): Response {
  const cursor = new URL(request.url).searchParams.get("cursor");
  const page: ExecutionPage =
    cursor === "c2" ? { items: [later], next_cursor: null } : { items: [committed, denied], next_cursor: "c2" };
  return json(page);
}

function mount(initial: string, answers: Record<string, unknown> = {}) {
  const calls = serve({
    "/api/console/v1/session": session,
    [LIST]: pages,
    [`/api/console/v1/executions/${COMMITTED}`]: detail,
    ...answers,
  });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [initial] }) });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { calls, router, client };
}

/** The shell's after-paint layer, which holds the keyboard and the live region, is in place. */
async function afterPaint(): Promise<void> {
  await waitFor(() => {
    expect(document.querySelector("[data-announcer]")).not.toBeNull();
  });
}

async function rows(): Promise<HTMLElement[]> {
  const table = await screen.findByRole("table", { name: /Activity/ });
  return within(table).getAllByRole("row");
}

async function row(index: number): Promise<HTMLElement> {
  const found = (await rows())[index];
  if (found === undefined) throw new Error(`No row ${String(index)}`);
  return found;
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
  clearToasts();
});

describe("Activity", () => {
  it("reads its filters from the URL, offers the next page and pins a filter a link set", async () => {
    const user = userEvent.setup();
    const { calls, router } = mount("/activity?state=UNCERTAIN&since=24h&agent=p-agent");
    await screen.findByRole("heading", { level: 1, name: "Activity" });
    expect(screen.getByRole("button", { name: "Uncertain" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "24 hours" })).toHaveAttribute("aria-pressed", "true");
    expect((await rows()).length).toBe(3);
    // The chip names the agent by the rows loaded under its filter (#678), not by an id.
    expect(screen.getByRole("button", { name: "Remove the agent filter" })).toHaveTextContent("triage-agent-b Agent 2");
    await waitFor(() => {
      expect(calledWith(calls, "GET", LIST, { state: "UNCERTAIN", since: "24h", agent: "p-agent" })).toBe(true);
    });
    expect(screen.getByText(/waiting for provider evidence/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => {
      expect(router.state.location.search).toMatchObject({ cursor: "c2" });
    });
    await waitFor(() => {
      expect(calledWith(calls, "GET", LIST, { state: "UNCERTAIN", since: "24h", agent: "p-agent", cursor: "c2" })).toBe(true);
    });
    await screen.findByRole("button", { name: "First page" });
    await waitFor(async () => {
      expect((await rows()).length).toBe(2);
    });
    await user.click(screen.getByRole("button", { name: "Remove the agent filter" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "UNCERTAIN", since: "24h" });
    });
    await user.click(screen.getByRole("button", { name: "Denied" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "DENIED", since: "24h" });
    });
  });

  it("pins a report's outcome and start, sends both, and drops what it does not know (#678)", async () => {
    expect(activitySearch({ outcome: "lapsed", from: "2026-10-01T00:00:00Z" })).toMatchObject({
      outcome: "lapsed",
      from: "2026-10-01T00:00:00Z",
    });
    expect(activitySearch({ outcome: "x", from: "yesterday" })).toMatchObject({ outcome: undefined, from: undefined });
    expect(activitySearch({ from: "2026-10-01T00:00:00Z".padEnd(41, "0") }).from).toBeUndefined();
    expect(filters({ outcome: "lapsed", from: "2026-10-01T00:00:00Z" })).toEqual({
      outcome: "lapsed",
      from: "2026-10-01T00:00:00Z",
    });
    const user = userEvent.setup();
    const { calls, router } = mount("/activity?outcome=lapsed&from=2026-09-12T14%3A00%3A00Z");
    await screen.findByRole("heading", { level: 1, name: "Activity" });
    await waitFor(() => {
      expect(calledWith(calls, "GET", LIST, { outcome: "lapsed", from: "2026-09-12T14:00:00Z" })).toBe(true);
    });
    expect(screen.getByRole("button", { name: "Remove the outcome filter" })).toHaveTextContent("Lapsed before a decision");
    expect(screen.getByRole("button", { name: "Remove the from filter" })).toHaveTextContent(/^Since /);
    await user.click(screen.getByRole("button", { name: "Remove the outcome filter" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ from: "2026-09-12T14:00:00Z" });
    });
    // A relative window replaces the report's start, which the server takes alone.
    await user.click(screen.getByRole("button", { name: "24 hours" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ since: "24h" });
    });
  });

  it("reconciles from the drawer, waiting for the server, and says what it settled", async () => {
    const user = userEvent.setup();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((done) => {
      release = done;
    });
    const posted: unknown[] = [];
    const { router } = mount("/activity?state=UNCERTAIN", {
      [RECONCILE]: async (_request: Request, body: unknown) => {
        posted.push(body);
        await gate;
        return json({ execution_id: COMMITTED, state: "FAILED_NOT_EXECUTED", state_label: "Not executed" });
      },
    });
    await user.click(within(await row(1)).getByRole("button", { name: "Reconcile" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "UNCERTAIN", open: COMMITTED });
    });
    const dialog = await screen.findByRole("dialog", { name: "Reconcile with provider evidence" });
    const submit = within(dialog).getByRole("button", { name: "Reconcile with provider evidence" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Reason"), "Lost the ticket holder");
    expect(submit).toBeEnabled();
    await user.click(submit);
    await waitFor(() => {
      expect(posted).toHaveLength(1);
    });
    expect(within(dialog).getByRole("button", { name: "Waiting for the server" })).toBeDisabled();
    expect(posted[0]).toEqual({
      continuation: "cont-1",
      reason: "Lost the ticket holder",
      cancel_if_missing: false,
      record: null,
    });
    release();
    await screen.findByText("Settled: Not executed.");
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Reconcile with provider evidence" })).toBeNull();
    });
    expect(screen.getByRole("dialog", { name: "Isolate endpoint ws07" })).toBeInTheDocument();
  });

  it("shows a refusal as copy and lets the person try again", async () => {
    const user = userEvent.setup();
    mount(`/activity?state=UNCERTAIN&open=${COMMITTED}`, {
      [RECONCILE]: () => json({ code: "INVALID_CONTINUATION", detail: "The record changed since it was read." }, 400),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    await user.click(within(drawer).getByRole("button", { name: "Reconcile" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconcile with provider evidence" });
    await user.type(within(dialog).getByLabelText("Reason"), "Try");
    await user.click(within(dialog).getByRole("checkbox", { name: "Cancel if no terminal evidence exists" }));
    await user.click(within(dialog).getByRole("button", { name: "Reconcile with provider evidence" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "The record changed since it was read. Close it and open it again.",
    );
    expect(within(dialog).getByRole("button", { name: "Reconcile with provider evidence" })).toBeEnabled();
  });

  it("explains a credential-shaped reason by name rather than the dialog's generic line", async () => {
    const user = userEvent.setup();
    mount(`/activity?state=UNCERTAIN&open=${COMMITTED}`, {
      [RECONCILE]: () => json({ code: "INVALID_BODY", detail: "Invalid body", fields: ["reason"] }, 400),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    await user.click(within(drawer).getByRole("button", { name: "Reconcile" }));
    const dialog = await screen.findByRole("dialog", { name: "Reconcile with provider evidence" });
    // The server, not the console, decides this is credential-shaped; the mock stands in for
    // that refusal regardless of what was typed, as the existing INVALID_CONTINUATION test
    // above types "Try" rather than reproducing a stale record.
    await user.type(within(dialog).getByLabelText("Reason"), "Pasted the wrong field from the ticket");
    await user.click(within(dialog).getByRole("button", { name: "Reconcile with provider evidence" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "A reason of 1 to 500 characters is required, with nothing in it that looks like a password, key or token.",
    );
  });

  it("shows the records a signal fact rested on, each producer string isolated as text", async () => {
    // The gateway refuses a verdict holding a directional override; the console isolates one
    // anyway, so a string that did arrive could not reorder the words around it.
    const verdict = "Medium\u202E<img src=x onerror=alert(1)>";
    const label = "MDE\u202E lab";
    const expires = "2026-09-19T14:05:41Z";
    // Observed half a minute before it was received, so the two instants cannot be swapped.
    const observed = "2026-09-19T14:01:41Z";
    const signal: ExecutionDetail = {
      ...detail,
      facts: [{
        name: "compromise", value: "compromised", origin: "RESOLVED", source_kind: "signal",
        source_object_id: "ws07", source_version: "2", observed_at: NOW, valid_until: "2026-09-19T14:06:11Z",
        capability: "resource_compromise.v1", source_label: label,
        records: [{
          source_id: "5e5e5e5e-0000-4000-8000-000000000005", registration_version: 2, attests_liveness: false,
          source_event_id: "ws07:\u202E1716", record_digest: "cd".repeat(32),
          producer_name: "execbound-mde-producer", producer_version: "0.1.0",
          verdict, confidence: 1000, observed_at: observed, received_at: NOW, expires_at: expires,
        }],
      }],
    };
    mount(`/activity?open=${COMMITTED}`, { [`/api/console/v1/executions/${COMMITTED}`]: signal });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    for (const text of [label, verdict, "ws07:\u202E1716", "execbound-mde-producer", "0.1.0"]) {
      const isolated = within(drawer).getByText(text);
      expect(isolated.tagName).toBe("BDI");
      expect(isolated.textContent).toBe(text);
    }
    expect(within(drawer).getByText(label).parentElement).toHaveTextContent(`${label} (resource_compromise.v1)`);
    expect(within(drawer).getByText(/registration version 2, does not attest liveness/)).toBeInTheDocument();
    expect(within(drawer).getByText(/^Observed/)).toHaveTextContent(
      `Observed ${dateTime(observed)}, received ${dateTime(NOW)}; the producer set its expiry to ${dateTime(expires)}.`,
    );
    expect(within(drawer).getByText("cd".repeat(32))).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("names a signal fact's source and capability without records, as an approver reads it", async () => {
    const signal: ExecutionDetail = {
      ...detail,
      facts: [{
        name: "compromise", value: "no_detection", origin: "RESOLVED", source_kind: "signal",
        source_object_id: "ws07", source_version: "1", observed_at: NOW, valid_until: "2026-09-19T14:06:11Z",
        capability: "resource_compromise.v1", source_label: "MDE lab", records: null,
      }],
    };
    mount(`/activity?open=${COMMITTED}`, { [`/api/console/v1/executions/${COMMITTED}`]: signal });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    expect(within(drawer).getByText("MDE lab").parentElement).toHaveTextContent("MDE lab (resource_compromise.v1)");
    expect(within(drawer).queryByText("Signal records")).toBeNull();
  });

  it.each(["PENDING", "APPROVED"])("opens a %s approval itself from the drawer, not the queue", async (state) => {
    // The approvals page asks whether it is on a phone; jsdom has no media queries.
    vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }));
    const user = userEvent.setup();
    const { calls, router } = mount(`/activity?open=${COMMITTED}`, {
      [`/api/console/v1/executions/${COMMITTED}`]: withApproval(state),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    const link = within(drawer).getByRole("link", { name: "Open in Approvals" });
    expect(link).toHaveAttribute("href", `/approvals/${APPROVAL}`);
    await user.click(link);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`/approvals/${APPROVAL}`);
    });
    // The approval is read by its own id, which is what names the space that owns it; this
    // administrator holds no scope over it, so the answer is the approval page's own refusal.
    await waitFor(() => {
      expect(called(calls, "GET", `/api/console/v1/approvals/${APPROVAL}`)).toBe(true);
    });
    expect(await screen.findByText("This approval is not in your scope.")).toBeInTheDocument();
  });

  it("offers the approval to a person who decides approvals in another of their spaces", async () => {
    // Looking at a space where they only read, while deciding approvals in another: the
    // record is read by membership, so the link asks what they hold anywhere, not here.
    const elsewhere: SessionView = {
      ...session,
      identity: { principal_id: "p-member", kind: "HUMAN_APPROVER", label: "M. Chen" },
      access: {
        managed: true, roles: ["approver", "viewer"], permissions: ["console.read", "approvals.decide"],
        workspace_permissions: [],
        space_permissions: { [READING]: ["console.read"], [DECIDING]: ["approvals.decide", "console.read"] },
      },
      space: { space_id: READING, name: "Northwind", archived: false },
      spaces: 2,
    };
    mount(`/activity?open=${COMMITTED}`, {
      "/api/console/v1/session": elsewhere,
      [`/api/console/v1/executions/${COMMITTED}`]: withApproval("PENDING"),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    expect(within(drawer).getByRole("link", { name: "Open in Approvals" })).toHaveAttribute(
      "href",
      `/approvals/${APPROVAL}`,
    );
  });

  it("offers no approval link to a person who decides approvals nowhere", async () => {
    const viewer: SessionView = {
      ...session,
      identity: { principal_id: "p-viewer", kind: "HUMAN_APPROVER", label: "V. Osei" },
      access: {
        managed: true, roles: ["viewer"], permissions: ["console.read"], workspace_permissions: [],
        space_permissions: {},
      },
    };
    mount(`/activity?open=${COMMITTED}`, {
      "/api/console/v1/session": viewer,
      [`/api/console/v1/executions/${COMMITTED}`]: withApproval("PENDING"),
    });
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    // The approval is still described; only the door the approval page would refuse is gone.
    expect(within(drawer).getByText(/Waiting for a person/)).toBeInTheDocument();
    expect(within(drawer).queryByRole("link", { name: "Open in Approvals" })).toBeNull();
  });

  it("moves along the rows with j and k, and offers no settlement where none is offered", async () => {
    const user = userEvent.setup();
    mount("/activity");
    const first = await row(1);
    const second = await row(2);
    await afterPaint();
    expect(within(second).queryByRole("button", { name: "Reconcile" })).toBeNull();
    await user.keyboard("j");
    expect(document.activeElement).toBe(within(first).getByRole("button", { name: "Isolate endpoint" }));
    await user.keyboard("j");
    expect(document.activeElement).toBe(within(second).getByRole("button", { name: "Isolate endpoint" }));
    await user.keyboard("k");
    expect(document.activeElement).toBe(within(first).getByRole("button", { name: "Isolate endpoint" }));
    await user.click(screen.getByRole("button", { name: "Compact rows" }));
    expect(screen.getByRole("table", { name: /Activity/ })).toHaveClass("table-compact");
  });

  it("keeps the focus on a filter chip it changed, and announces what the filter found once (NV14, #678)", async () => {
    const user = userEvent.setup();
    const { client } = mount("/activity");
    await rows();
    await afterPaint();
    const region = document.querySelector("[data-announcer]");
    const held = screen.getByRole("button", { name: "Held" });
    await user.click(held);
    await waitFor(() => {
      expect(region).toHaveTextContent("More than 50 actions match; showing the newest 50");
    });
    expect(held).toHaveFocus();
    // A poll refresh with the same filters says nothing again.
    if (region !== null) region.textContent = "";
    await act(async () => {
      await client.refetchQueries({ type: "active" });
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(region).toHaveTextContent("");
  });

  it("returns the focus to the row it was opened from when the drawer closes (NV14, #678)", async () => {
    const user = userEvent.setup();
    mount("/activity");
    const button = within(await row(1)).getByRole("button", { name: "Isolate endpoint" });
    button.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(document.querySelector(`[data-record-id="${COMMITTED}"]`));
    });
  });

  it("lands on the record's row when a drawer opened from an address closes (NV14, #678)", async () => {
    const user = userEvent.setup();
    mount(`/activity?open=${COMMITTED}`);
    await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    // The table under the open drawer is hidden from the accessibility tree.
    await waitFor(() => {
      expect(document.querySelector(`[data-record-id="${COMMITTED}"]`)).not.toBeNull();
    });
    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(document.activeElement).toBe(document.querySelector(`[data-record-id="${COMMITTED}"]`));
    });
  });

  it("offers no disabled Explain, and one real Explain below the record where there is an assistant (NV17, #678)", async () => {
    mount(`/activity?open=${COMMITTED}`);
    const drawer = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    expect(within(drawer).queryByRole("button", { name: /^Explain/ })).toBeNull();
    cleanup();
    vi.unstubAllGlobals();
    mount(`/activity?open=${COMMITTED}`, {
      "/api/console/v1/session": { ...session, assistant: true },
      "/api/console/v1/assistant/settings": ASSISTANT_ON,
    });
    const assisted = await screen.findByRole("dialog", { name: "Isolate endpoint ws07" });
    const explain = await within(assisted).findAllByRole("button", { name: /^Explain/ });
    expect(explain).toHaveLength(1);
    expect(explain[0]).toHaveAccessibleName("Explain this decision");
    expect(explain[0]).toBeEnabled();
  });

  it("keeps the list it read through a poll that fails", async () => {
    let reads = 0;
    const { client } = mount("/activity", {
      [LIST]: (request: Request) =>
        ++reads === 1 ? pages(request) : json({ code: "UNAVAILABLE", detail: "Unavailable." }, 503),
    });
    expect(await rows()).toHaveLength(3);
    await act(async () => {
      await client.refetchQueries({ type: "active" });
    });
    expect(await screen.findByText("Activity could not load.")).toBeInTheDocument();
    expect(reads).toBe(2);
    expect(await rows()).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Next page" })).toBeInTheDocument();
  });
});

describe("an empty Activity list (UX16, #678)", () => {
  const EMPTY = { items: [], next_cursor: null };

  it("tells an administrator nothing has arrived yet and opens guided setup", async () => {
    mount("/activity", { [LIST]: EMPTY });
    const empty = await screen.findByText("No agent has sent a request in this view yet.", { exact: false });
    expect(within(empty).getByRole("link", { name: "Open guided setup" })).toHaveAttribute("href", "/welcome?step=connect");
  });

  it("tells an approver where their requests appear", async () => {
    const approver: SessionView = {
      ...session,
      identity: { principal_id: "p-approver", kind: "HUMAN_APPROVER", label: "B. Chen" },
      access: { managed: false, roles: ["approver"], permissions: ["console.read", "approvals.decide"], workspace_permissions: [], space_permissions: {} },
    };
    mount("/activity", { [LIST]: EMPTY, "/api/console/v1/session": approver });
    expect(await screen.findByText("Requests in your review scope appear here.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Open guided setup" })).toBeNull();
  });

  it("keeps the filtered wording for a filtered list", async () => {
    mount("/activity?state=DENIED", { [LIST]: EMPTY });
    expect(await screen.findByText("No actions match these filters.")).toBeInTheDocument();
    expect(screen.queryByText(/No agent has sent a request/)).toBeNull();
  });
});
