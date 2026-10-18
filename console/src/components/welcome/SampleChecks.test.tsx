// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listApprovalsOptions } from "../../api/@tanstack/react-query.gen";
import type { ApprovalItem, SampleHostView, SampleStatusView, TenantSettingsView } from "../../api/types.gen";
import { dateTime } from "../../lib/words";
import { called, calledWith, json, serve } from "../../test/api";
import { renderPage } from "../../test/page";
import { deadlineWords, RETIRE_TO_REFRESH } from "./held";
import { BARE_DENIAL, NO_DESTINATION, SampleChecks } from "./SampleChecks";

const APPROVALS = "/api/console/v1/approvals";
const CONNECTION = "/api/console/v1/connection";
const TENANT = "/api/console/v1/tenant";
const OBSERVED = "2026-09-24T10:00:00+00:00";
const STALE = "2026-09-24T11:00:00+00:00";
const LATER = "2099-09-24T11:00:00+00:00";
const CLOSES = "2026-09-24T10:07:00+00:00";
const LAPSE = "If nobody approves it in time, or it is approved but your agent does not send it again before the deadline, it lapses, and your agent has to make a new request.";
const APPROVAL = "44444444-0000-4000-8000-000000000007";
const RETIRE = "A policy made from the starter policy, by copying it or from a template, stops a refresh until it is retired in Policies; if it is the active policy, activate the starter policy again first, then retire it.";
const REFERENCES = "Each new request needs a new reference from your agent, the ticket, case or run id it sends: on the same target, a reference already recorded brings back the request recorded under it, even with a new incident. Your agent should reuse one only to send the same request again, as after you approve it.";

function sampleHost(provider_id: string, hostname: string, role: string, effect: string, incident: number): SampleHostView {
  return { provider_id, hostname, role, environment: "production", criticality: 2, incident_id: `22222222-0000-4000-8000-00000000000${String(incident)}`, effect, rules: [] };
}

const SAMPLES: SampleStatusView = {
  state: "removable",
  offered: false,
  available: true,
  demo_available: true,
  demo_needs_refresh: false,
  bundle_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  hosts: [
    sampleHost("sample-dc-01", "dc-01.sample.invalid", "domain_controller", "deny", 3),
    sampleHost("sample-ws-dev-01", "ws-dev-01.sample.invalid", "workstation", "allow", 1),
    sampleHost("sample-ws-prod-01", "ws-prod-01.sample.invalid", "workstation", "require approval", 2),
  ],
  observed_at: OBSERVED,
  stale_at: STALE,
  first_request: null,
};
/** The same samples with facts that are still current. */
const CURRENT: SampleStatusView = { ...SAMPLES, stale_at: LATER };

const CONNECTED = {
  origin: "http://console.test",
  recipes: {},
  workstation: { kind: "hostname", value: "ws-dev-01.sample.invalid", incident_id: "22222222-0000-4000-8000-000000000001" },
  operation_ref: "op.from-the-server",
  samples_state: "removable",
};

function approval(changes: Partial<ApprovalItem> = {}): ApprovalItem {
  return {
    approval_id: APPROVAL,
    request_ref: "EB-7",
    external_case: null,
    execution_id: "33333333-0000-4000-8000-000000000007",
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    target: "sample-ws-prod-01",
    resource_class: "workstation",
    environment: "production",
    agent: { principal_id: "55555555-0000-4000-8000-000000000001", label: "Responder", number: 1 },
    created_at: "2026-09-24T10:05:00+00:00",
    expires_at: CLOSES,
    total_seconds: 120,
    deadline_clock: "approval deadline",
    approval_state: "PENDING",
    execution_state: "PENDING_APPROVAL",
    execution_state_label: "Held",
    required: 1,
    recorded: 0,
    mine: null,
    decided_at: null,
    notified: null,
    ...changes,
  };
}

function tenant(seconds: number | null, changes: Partial<TenantSettingsView> = {}): TenantSettingsView {
  return {
    tenant_id: "7f8e9d0c-0000-4000-8000-000000000003",
    tenant_name: "Synthetic SOC",
    mode: { value: "ENFORCE", changed: null },
    deadline: { seconds, bounds: { min: 120, max: 3600 }, changed: null },
    stop: null,
    bundle_id: null,
    monitoring: { sources: 0, reporting: 0, stale: 0, overdue: 0, open_findings: 0 },
    destinations: [],
    delivery: { window_days: 7, delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null, lapsed: 0, failed: 0 },
    approval_windows: [],
    ...changes,
  };
}

/** Both approval lists from one route, answered by the `view` each request names. */
function lists(pending: ApprovalItem[], lapsed: ApprovalItem[] = []) {
  return (request: Request) => {
    const view = new URL(request.url).searchParams.get("view") ?? "pending";
    return json({ view, items: view === "lapsed" ? lapsed : pending, next_cursor: null, server_time: CLOSES });
  };
}

/** Renders once the Lapsed list has answered, from the query the held line reads, which it never starts. */
function LapsedAnswered() {
  const lapsed = useQuery({ ...listApprovalsOptions({ query: { view: "lapsed" } }), enabled: false });
  return lapsed.isFetched ? <p>Lapsed answered</p> : null;
}

function line(hostname: string): HTMLElement {
  const item = screen.getByText(hostname).closest("li");
  if (item === null) throw new Error(`no line for ${hostname}`);
  return item;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("the sample lines in Verify protection (#545)", () => {
  it("names the operation the server gives, each target's hostname and its incident", async () => {
    serve({ [CONNECTION]: CONNECTED });
    renderPage(<SampleChecks samples={SAMPLES} />);
    expect(await screen.findAllByText("op.from-the-server")).toHaveLength(3);
    expect(screen.getByText("ws-dev-01.sample.invalid").closest("p")).toHaveTextContent(
      "No request on a sample target yet. Ask your agent to call execute with operation_ref op.from-the-server, target hostname ws-dev-01.sample.invalid and claimed_context.incident_id 22222222-0000-4000-8000-000000000001.",
    );
    expect(line("dc-01.sample.invalid")).toHaveTextContent("Ask it to call execute with operation_ref op.from-the-server, target hostname dc-01.sample.invalid and claimed_context.incident_id 22222222-0000-4000-8000-000000000003.");
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(
      "Ask it to call execute with operation_ref op.from-the-server, target hostname ws-prod-01.sample.invalid and claimed_context.incident_id 22222222-0000-4000-8000-000000000002. A production target waits for approval in Approvals; approve it there, and it executes when your agent sends the same request again.",
    );
  });

  it("names only the target and its incident until the server names an operation", async () => {
    const calls = serve({});
    renderPage(<SampleChecks samples={SAMPLES} />);
    await waitFor(() => { expect(called(calls, "GET", CONNECTION)).toBe(true); });
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent("Ask it to isolate ws-prod-01.sample.invalid for incident 22222222-0000-4000-8000-000000000002.");
    expect(screen.queryByText("operation_ref", { exact: false })).toBeNull();
  });

  it("prepares the person for a bare denial in the terms the agent's answer uses", async () => {
    const calls = serve({});
    renderPage(<SampleChecks samples={SAMPLES} />);
    await waitFor(() => { expect(called(calls, "GET", CONNECTION)).toBe(true); });
    expect(line("dc-01.sample.invalid")).toHaveTextContent("The starter policy denies a domain controller, so the request stops before the endpoint.");
    // One disclosure away (#678): closed, the words are there and not shown; opened, they are.
    const told = screen.getByText(BARE_DENIAL);
    expect(told.closest("details")?.querySelector("summary")).toHaveTextContent("What your agent is told when it is denied");
    expect(told).not.toBeVisible();
    await userEvent.click(screen.getByText("What your agent is told when it is denied"));
    expect(told).toBeVisible();
    expect(BARE_DENIAL).toBe(
      "Your agent is told that the request was denied and given its reference, such as EB-12, but not why: the reason is recorded for you, and searching the console for that reference finds it. The only causes an agent is ever told are that another request holds the target or that a shared limit is spent. Re-sending the same request returns the same answer.",
    );
  });

  it("says each new request needs a new reference, since a recorded one brings back its request whatever incident it names", async () => {
    serve({ [CONNECTION]: CONNECTED });
    renderPage(<SampleChecks samples={SAMPLES} />);
    const words = await screen.findByText(/^Each new request needs a new/);
    expect(words).toHaveTextContent(REFERENCES);
    expect(words).not.toBeVisible();
    await userEvent.click(screen.getByText("Why each new request needs a new reference"));
    expect(words).toBeVisible();
    // The field the agent sends is code, told apart from the EB number the denial calls a reference.
    expect([...words.querySelectorAll("code")].map((element) => element.textContent)).toEqual(["reference", "reference"]);
  });

  it("says stale sample facts refuse every request until they are refreshed, and says nothing while they are current", async () => {
    const calls = serve({});
    const { unmount } = renderPage(<SampleChecks samples={SAMPLES} />);
    await waitFor(() => { expect(called(calls, "GET", CONNECTION)).toBe(true); });
    const note = screen.getByText(/^The sample facts went stale at/);
    expect(note).toHaveAttribute("role", "status");
    expect(note).toHaveTextContent(
      `The sample facts went stale at ${dateTime(STALE)}: every request on them is refused, and your agent is told only that execution is unavailable, until you refresh them in Try an example. ${RETIRE}`,
    );
    expect(RETIRE_TO_REFRESH).toBe(RETIRE);
    expect(note).toHaveClass("notice", "notice-hold");
    unmount();
    renderPage(<SampleChecks samples={CURRENT} />);
    expect(await screen.findByText("ws-prod-01.sample.invalid")).toBeInTheDocument();
    expect(screen.queryByText(/^The sample facts went stale at/)).toBeNull();
  });

  it("says the facts went stale when they do, with the page left open and nothing new to read", async () => {
    // Verify protection polls the status, but an unchanged answer re-renders nothing, so the note
    // needs a clock of its own to appear.
    vi.useFakeTimers({ now: Date.parse(STALE) - 10_000 });
    serve({ [CONNECTION]: CONNECTED });
    renderPage(<SampleChecks samples={SAMPLES} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    // Every read of the lines has answered, so nothing but the clock is left to change them.
    expect(screen.getAllByText("op.from-the-server")).toHaveLength(3);
    expect(screen.queryByText(/^The sample facts went stale at/)).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(screen.getByText(/^The sample facts went stale at/)).toHaveTextContent(`The sample facts went stale at ${dateTime(STALE)}:`);
  });

  it("states the workspace's own deadline, capped by when the sample facts go stale", async () => {
    serve({ [TENANT]: tenant(120) });
    renderPage(<SampleChecks samples={CURRENT} />);
    await waitFor(() => {
      expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(
        `A request waits for approval for up to 2 minutes, this workspace's approval deadline, and never past ${dateTime(LATER)}, when the sample facts go stale. ${LAPSE}`,
      );
    });
  });

  it("says a deadline that is off is off, where the session would read two minutes", async () => {
    serve({ [TENANT]: tenant(null) });
    renderPage(<SampleChecks samples={CURRENT} />);
    await waitFor(() => {
      expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(`This workspace has no approval deadline, so a request waits for approval no later than ${dateTime(LATER)}, when the sample facts go stale. ${LAPSE}`);
    });
  });

  it("bounds the deadline by no stale time once the facts are stale, since that moment has gone", async () => {
    serve({ [TENANT]: tenant(120) });
    renderPage(<SampleChecks samples={SAMPLES} />);
    await waitFor(() => {
      expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(`A request waits for approval for up to 2 minutes, this workspace's approval deadline. ${LAPSE}`);
    });
    expect(line("ws-prod-01.sample.invalid")).not.toHaveTextContent("never past");
  });

  it("states how fast notifications arrive right after the deadline, or that none are sent (#678)", async () => {
    serve({
      [TENANT]: tenant(600, {
        destinations: [{ destination_id: "soc", kind: "webhook", host: "alerts.example.net", approvers: null, messages: ["pending"] }],
        delivery: { window_days: 7, delivered: 6, median_seconds: 40, p90_seconds: 70, slowest_seconds: 95, lapsed: 0, failed: 0 },
      }),
    });
    renderPage(<SampleChecks samples={CURRENT} />);
    const said = "Last 7 days: 6 notifications delivered. Half arrived within 40 s, nine in ten within 70 s.";
    const delivery = await screen.findByText(said);
    const deadline = screen.getByText(/this workspace's approval deadline/);
    expect(deadline.nextElementSibling).toBe(delivery);
    expect(delivery).toHaveClass("muted");
  });

  it("says a held request is announced only in this console where no destination is configured", async () => {
    serve({ [TENANT]: tenant(120) });
    renderPage(<SampleChecks samples={CURRENT} />);
    const none = await screen.findByText(NO_DESTINATION);
    expect(screen.getByText(/this workspace's approval deadline/).nextElementSibling).toBe(none);
    expect(NO_DESTINATION).toBe("No notification destination is configured, so a held request is announced only in this console.");
  });

  it("says nothing of delivery before the tenant is read", async () => {
    serve({ [CONNECTION]: CONNECTED });
    renderPage(<SampleChecks samples={CURRENT} />);
    expect(await screen.findAllByText("op.from-the-server")).toHaveLength(3);
    expect(screen.queryByText(NO_DESTINATION)).toBeNull();
    expect(screen.queryByText(/notifications delivered/)).toBeNull();
  });

  it("words each deadline in its largest whole unit, and what is known before the tenant is read", () => {
    expect(deadlineWords(3600, STALE)).toContain("for up to 1 hour, this workspace's approval deadline");
    expect(deadlineWords(150, STALE)).toContain("for up to 150 seconds, this workspace's approval deadline");
    expect(deadlineWords(120, null)).toBe(`A request waits for approval for up to 2 minutes, this workspace's approval deadline. ${LAPSE}`);
    expect(deadlineWords(undefined, STALE)).toBe(`A request never waits past ${dateTime(STALE)}, when the sample facts go stale. ${LAPSE}`);
    expect(deadlineWords(undefined, null)).toBe(LAPSE);
  });

  it("links the held target's own pending approval and says when it closes", async () => {
    const calls = serve({
      [APPROVALS]: lists([
        approval({ approval_id: "44444444-0000-4000-8000-000000000009", request_ref: "EB-9", target: "sample-ws-dev-01" }),
        approval({ approval_id: "44444444-0000-4000-8000-000000000002", request_ref: "EB-2", created_at: "2026-09-24T09:55:00+00:00" }),
        approval(),
      ]),
    });
    renderPage(<SampleChecks samples={SAMPLES} />);
    expect(await screen.findByRole("link", { name: "EB-7" })).toHaveAttribute("href", `/approvals/${APPROVAL}`);
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(`Waiting now: EB-7, open until ${dateTime(CLOSES)}.`);
    expect(screen.queryByRole("link", { name: "EB-9" })).toBeNull();
    expect(screen.queryByRole("link", { name: "EB-2" })).toBeNull();
    expect(calledWith(calls, "GET", APPROVALS, { view: "lapsed" })).toBe(false);
  });

  it("says when a pending approval closes where the plan's own validity set it", async () => {
    serve({ [APPROVALS]: lists([approval({ deadline_clock: "context validity", expires_at: STALE })]) });
    renderPage(<SampleChecks samples={SAMPLES} />);
    await screen.findByRole("link", { name: "EB-7" });
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(`Waiting now: EB-7, open until ${dateTime(STALE)}, when its facts go stale or your agent's API key expires, whichever is first.`);
  });

  it("names a lapsed approval that still holds the samples, and that the recovery run ends it", async () => {
    const calls = serve({ [APPROVALS]: lists([], [approval()]) });
    renderPage(<SampleChecks samples={SAMPLES} />);
    expect(await screen.findByRole("link", { name: "EB-7" })).toHaveAttribute("href", `/approvals/${APPROVAL}`);
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(
      `EB-7 lapsed at ${dateTime(CLOSES)} before it executed. Ask the agent that made it to send the same request again: that ends it, and a new request after that, with a new reference, waits for a new approval while the sample facts are current. Otherwise ExecBound ends it at a scheduled recovery run, within about twenty minutes of the lapse; until it ends, the sample targets cannot be refreshed or removed.`,
    );
    // `reference` is the field the agent sends, never the request's EB number.
    expect(within(line("ws-prod-01.sample.invalid")).getAllByText("reference").map((element) => element.tagName)).toEqual(["CODE"]);
    expect(calledWith(calls, "GET", APPROVALS, { view: "lapsed" })).toBe(true);
  });

  it("names only the newer pending approval once a second agent makes one after a lapse nothing has ended yet", async () => {
    // Only a second agent reaches this. The agent whose request lapsed has its next request on the
    // target matched to the lapsed one, which admission ends as STALE_AUTHORIZATION, so no newer
    // approval of its own waits beside the lapse. Another agent's request is an intent of its own,
    // and a held request takes no claim on the target, so it is admitted and waits for approval
    // while the lapse waits for the recovery run. The lapsed list, switched off once a pending
    // approval matches, keeps its last answer, which still names the lapse.
    let pending: ApprovalItem[] = [];
    serve({ [APPROVALS]: (request: Request) => lists(pending, [approval()])(request) });
    const { queryClient } = renderPage(<SampleChecks samples={SAMPLES} />);
    expect(await screen.findByRole("link", { name: "EB-7" })).toHaveAttribute("href", `/approvals/${APPROVAL}`);
    const newer = "44444444-0000-4000-8000-000000000008";
    pending = [approval({ approval_id: newer, request_ref: "EB-8", agent: { principal_id: "55555555-0000-4000-8000-000000000002", label: "Second responder", number: 2 }, created_at: "2026-09-24T10:20:00+00:00", expires_at: "2026-09-24T10:22:00+00:00" })];
    await act(async () => { await queryClient.refetchQueries({ queryKey: listApprovalsOptions({ query: { view: "pending" } }).queryKey }); });
    expect(await screen.findByRole("link", { name: "EB-8" })).toHaveAttribute("href", `/approvals/${newer}`);
    expect(line("ws-prod-01.sample.invalid")).toHaveTextContent(`Waiting now: EB-8, open until ${dateTime("2026-09-24T10:22:00+00:00")}.`);
    expect(screen.queryByRole("link", { name: "EB-7" })).toBeNull();
    expect(line("ws-prod-01.sample.invalid")).not.toHaveTextContent("lapsed at");
  });

  it("names no lapsed approval once the recovery run has ended it", async () => {
    serve({ [APPROVALS]: lists([], [approval({ approval_state: "EXPIRED", execution_state: "STALE_AUTHORIZATION" })]) });
    renderPage(<><SampleChecks samples={SAMPLES} /><LapsedAnswered /></>);
    // The sentinel renders from the same answer as the held line, so the line has had it too.
    expect(await screen.findByText("Lapsed answered")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "EB-7" })).toBeNull();
    expect(line("ws-prod-01.sample.invalid")).not.toHaveTextContent("lapsed at");
  });

  it("gives no stale advice after a lapse the recovery run ended and a newer request that was approved and executed", async () => {
    const executed = { execution_id: "33333333-0000-4000-8000-000000000008", state: "EXECUTED", state_label: "Executed", provider_id: "sample-ws-prod-01", created_at: "2026-09-24T10:20:00+00:00" };
    serve({ [APPROVALS]: lists([], [approval({ approval_state: "EXPIRED", execution_state: "STALE_AUTHORIZATION" })]) });
    renderPage(<><SampleChecks samples={{ ...SAMPLES, first_request: executed }} /><LapsedAnswered /></>);
    expect(await screen.findByRole("link", { name: "sample-ws-prod-01" })).toHaveAttribute("href", `/activity?open=${executed.execution_id}`);
    expect(await screen.findByText("Lapsed answered")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "EB-7" })).toBeNull();
    expect(screen.queryByText(/lapsed at/)).toBeNull();
  });
});
