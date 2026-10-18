// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readExecutionQueryKey } from "../api/@tanstack/react-query.gen";
import type { ExecutionSummary } from "../api/types.gen";
import { serve } from "../test/api";
import { ExecutionDrawer } from "./ExecutionDrawer";
import { note, PREFETCH_MS, RecordTable } from "./RecordTable";

/** The table where the console renders it, inside a query client. */
function withClient(ui: ReactNode, client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

const SAMPLE: ExecutionSummary = {
  request_ref: "EB-7",
  external_case: null,
  execution_id: "44444444-0000-4000-8000-000000000001",
  created_at: "2026-09-24T10:05:00Z",
  changed_at: "2026-09-24T10:05:01Z",
  state: "EXECUTED",
  state_label: "Executed",
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  target: { canonical_target_id: "c-7", provider_id: "sample-ws-dev-01", resource_class: "workstation", environment: "development", sample: true },
  agent: { principal_id: "p-agent", label: null, kind: "AGENT", number: 1 },
  approval: null,
  reasons: [],
  reconcile: { available: false, kind: null, continuation: null },
};

describe("the record table", () => {
  it("marks a request a sample account served, and only that one", () => {
    const configured: ExecutionSummary = {
      ...SAMPLE,
      execution_id: "44444444-0000-4000-8000-000000000002",
      target: { ...SAMPLE.target, provider_id: "ws07", sample: false },
    };
    withClient(<RecordTable caption="Records" items={[SAMPLE, configured]} open={undefined} onOpen={() => undefined} />);
    const [sample, other] = within(screen.getByRole("table", { name: "Records" })).getAllByRole("row").slice(1);
    if (sample === undefined || other === undefined) throw new Error("two rows expected");
    expect(within(sample).getByText("Sample")).toHaveClass("badge-accent");
    expect(other).not.toHaveTextContent("Sample");
  });

  it("says an approval lapsed when that is why a request went stale, as its record does", () => {
    const stale: ExecutionSummary = {
      ...SAMPLE,
      state: "STALE_AUTHORIZATION",
      state_label: "Stale",
      reasons: [{ code: "STALE_AUTHORIZATION", rule_id: null, sentence: "" }],
      approval: { approval_id: "a-3", expires_at: "2026-09-24T10:07:00Z", recorded: 0, required_approvers: 1, state: "EXPIRED" },
    };
    expect(note(stale)).toBe("The approval deadline passed before it could be used.");
    expect(note({ ...stale, reasons: [] })).toBe("The approval deadline passed before it could be used.");
    expect(note({ ...stale, state: "PENDING_APPROVAL", reasons: [] })).toBe("The approval deadline passed before it could be used.");
    // A stale request whose approval did not lapse keeps the general sentence, and a more
    // specific recorded reason still wins over the lapse.
    expect(note({ ...stale, approval: null })).toContain("no longer matches the current request conditions");
    expect(note({ ...stale, reasons: [{ code: "CONTEXT_EXPIRED", rule_id: null, sentence: "" }] })).toBe(
      "The trusted facts used for this request expired.",
    );
  });

  it("reads a held row whose approval lapsed, by the server's word, as lapsed (#678)", () => {
    const approval = {
      approval_id: "a-4",
      expires_at: "2026-09-24T10:07:00Z",
      recorded: 0,
      required_approvers: 1,
      state: "PENDING",
      lapsed: true,
      unused: false,
    };
    const held: ExecutionSummary = {
      ...SAMPLE,
      state: "PENDING_APPROVAL",
      state_label: "Held",
      reasons: [{ code: "APPROVAL_REQUIRED", rule_id: null, sentence: "A person has to approve it before it can run." }],
      approval,
    };
    expect(note(held)).toBe("The approval deadline passed before it could be used.");
    const unused: ExecutionSummary = {
      ...held,
      approval: { ...approval, state: "APPROVED", lapsed: false, unused: true },
    };
    expect(note(unused)).toBe("Approved, but not used before the deadline.");
    const waiting: ExecutionSummary = { ...held, approval: { ...approval, lapsed: false } };
    expect(note(waiting)).toBe("A person has to approve it before it can run.");
    withClient(<RecordTable caption="Records" items={[held, { ...unused, execution_id: "x-2" }, { ...waiting, execution_id: "x-3" }]} open={undefined} onOpen={() => undefined} />);
    const [first, second, third] = within(screen.getByRole("table", { name: "Records" })).getAllByRole("row").slice(1);
    if (first === undefined || second === undefined || third === undefined) throw new Error("three rows expected");
    expect(within(first).getByText("Lapsed")).toHaveClass("badge-stale");
    expect(within(second).getByText("Not used")).toHaveClass("badge-stale");
    expect(within(third).getByText("Held")).toBeInTheDocument();
  });

  it("says who confirmed an executed row and which rule a denied row matched (#545)", () => {
    const executed: ExecutionSummary = { ...SAMPLE, reasons: [{ code: "PROVIDER_RESPONSE", rule_id: null, sentence: "" }] };
    expect(note(executed)).toBe("The provider's own response confirmed this outcome.");
    const sentence = "This request matches the deny rule isolate-never-domain-controller: Deny endpoint.isolate when role is domain_controller.";
    const denied: ExecutionSummary = {
      ...SAMPLE,
      state: "DENIED",
      state_label: "Denied",
      reasons: [{ code: "NOT_AUTHORIZED", rule_id: null, sentence }],
    };
    expect(note(denied)).toBe(sentence);
  });
});

describe("a row's time (#678)", () => {
  it("prints the date before the time for a row from an earlier day, and the time alone for today", () => {
    const today = new Date(Date.now() - 60_000).toISOString();
    const earlier = new Date(Date.now() - 3 * 86_400_000).toISOString();
    withClient(
      <RecordTable
        caption="Records"
        items={[
          { ...SAMPLE, created_at: today },
          { ...SAMPLE, execution_id: "44444444-0000-4000-8000-000000000003", created_at: earlier },
        ]}
        open={undefined}
        onOpen={() => undefined}
      />,
    );
    const [first, second] = within(screen.getByRole("table", { name: "Records" })).getAllByRole("row").slice(1);
    if (first === undefined || second === undefined) throw new Error("two rows expected");
    const time = (row: HTMLElement) => row.querySelector("time")?.textContent ?? "";
    // Vitest runs in UTC, so the zone the column names is UTC and the dates are the ISO dates.
    expect(time(first)).toMatch(/^\d\d:\d\d:\d\d$/);
    expect(time(second)).toBe(`${earlier.slice(0, 10)} ${earlier.slice(11, 19)}`);
  });
});

describe("the drawer's badge (#678)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const record = (approval: ExecutionSummary["approval"]) => ({
    ...SAMPLE,
    state: "PENDING_APPROVAL",
    state_label: "Held",
    reasons: [{ code: "APPROVAL_REQUIRED", rule_id: null, sentence: "A person has to approve it before it can run." }],
    approval,
    timeline: [], arguments: [], facts: [], obligations: [], limits: [], checkpoint: [], carriers: [], deliveries: [],
    related_requests: [], dispatch: null, observed_effect: null, plan_hash: "ab".repeat(32), valid_until: SAMPLE.created_at,
    bundle_id: null, policy_readable: false,
  });
  const approval = { approval_id: "a-9", expires_at: "2026-09-24T10:07:00Z", recorded: 0, required_approvers: 1, state: "PENDING" };

  it.each([
    ["Lapsed", { ...approval, lapsed: true, unused: false }],
    ["Not used", { ...approval, state: "APPROVED", recorded: 1, lapsed: false, unused: true }],
    ["Held", { ...approval, lapsed: false, unused: false }],
  ])("reads %s, as the record's row in the list does", async (word, given) => {
    serve({ [`/api/console/v1/executions/${SAMPLE.execution_id}`]: record(given) });
    withClient(<ExecutionDrawer executionId={SAMPLE.execution_id} onClose={() => undefined} />);
    const drawer = await screen.findByRole("dialog");
    await within(drawer).findByText("Isolate endpoint sample-ws-dev-01");
    const badges = [...drawer.querySelectorAll(".badge")].map((badge) => badge.textContent);
    expect(badges[0]).toBe(word);
    withClient(<RecordTable caption="Row" items={[{ ...SAMPLE, state: "PENDING_APPROVAL", state_label: "Held", approval: given }]} open={undefined} onOpen={() => undefined} />);
    expect(within(screen.getByRole("table", { name: "Row" })).getByText(word)).toBeInTheDocument();
  });
});

describe("reading a record before it is opened (NV19, #678)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const reads = (calls: { path: string; method: string }[]) =>
    calls.filter((call) => call.method === "GET" && call.path === `/api/console/v1/executions/${SAMPLE.execution_id}`);

  it("reads the record once when a mouse rests on its row, and not for a touch", async () => {
    const calls = serve({ [`/api/console/v1/executions/${SAMPLE.execution_id}`]: { ...SAMPLE } });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const query = vi.spyOn(client, "query");
    withClient(<RecordTable caption="Records" items={[SAMPLE]} open={undefined} onOpen={() => undefined} />, client);
    const row = screen.getAllByRole("row")[1];
    if (row === undefined) throw new Error("no row");
    fireEvent.pointerEnter(row, { pointerType: "touch" });
    expect(query).not.toHaveBeenCalled();
    fireEvent.pointerEnter(row, { pointerType: "mouse" });
    expect(query).toHaveBeenCalledTimes(1);
    expect(query.mock.calls[0]?.[0]).toMatchObject({
      queryKey: readExecutionQueryKey({ path: { execution_id: SAMPLE.execution_id } }),
      staleTime: PREFETCH_MS,
    });
    await vi.waitFor(() => {
      expect(reads(calls)).toHaveLength(1);
    });
    fireEvent.pointerEnter(row, { pointerType: "mouse" });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(reads(calls)).toHaveLength(1);
  });

  it("reads it when the keyboard reaches its button, and the drawer then asks for nothing more", async () => {
    const calls = serve({ [`/api/console/v1/executions/${SAMPLE.execution_id}`]: { ...SAMPLE, timeline: [], arguments: [], facts: [], obligations: [], limits: [], checkpoint: [], carriers: [], deliveries: [], related_requests: [], dispatch: null, observed_effect: null, plan_hash: "ab".repeat(32), valid_until: SAMPLE.created_at, bundle_id: null, policy_readable: false } });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const view = withClient(<RecordTable caption="Records" items={[SAMPLE]} open={undefined} onOpen={() => undefined} />, client);
    screen.getByRole("button", { name: "Isolate endpoint" }).focus();
    await vi.waitFor(() => {
      expect(reads(calls)).toHaveLength(1);
    });
    view.rerender(
      <QueryClientProvider client={client}>
        <ExecutionDrawer executionId={SAMPLE.execution_id} onClose={() => undefined} />
      </QueryClientProvider>,
    );
    await screen.findByRole("dialog");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(reads(calls)).toHaveLength(1);
  });
});
