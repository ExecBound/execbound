// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { ExecutionSummary } from "../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../lib/session";
import { renderPage } from "../test/page";
import { PrincipalName } from "./PrincipalName";
import { RecordTable } from "./RecordTable";

const HOSTILE = "<img src=x onerror=alert(1)>";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", permissions: ["console.read", "access.manage"] };
const NARROW: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", permissions: ["console.read"] };
const APPROVER: SessionSummary = { ...PLACEHOLDER, role: "APPROVER", permissions: ["console.read", "approvals.decide"] };
const AGENT_ID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const PERSON_ID = "7d1e7b4a-0000-4000-8000-000000000002";

function row(agent: ExecutionSummary["agent"]): ExecutionSummary {
  return {
    request_ref: "EB-7",
    external_case: null,
    execution_id: "44444444-0000-4000-8000-000000000001",
    created_at: "2026-09-24T10:05:00Z",
    changed_at: "2026-09-24T10:05:01Z",
    state: "EXECUTED",
    state_label: "Executed",
    action: "endpoint.isolate",
    action_label: "Isolate endpoint",
    target: { canonical_target_id: "c-7", provider_id: "ws07", resource_class: "workstation", environment: "development", sample: false },
    agent,
    approval: null,
    reasons: [],
    reconcile: { available: false, kind: null, continuation: null },
  };
}

describe("one name per principal on a record (#678)", () => {
  it("names an unlabelled agent by its number and links it for an administrator", async () => {
    const onOpen = vi.fn();
    renderPage(<RecordTable caption="Records" items={[row({ principal_id: AGENT_ID, label: null, kind: "AGENT", number: 1 })]} open={undefined} onOpen={onOpen} />, ADMIN);
    const link = await screen.findByRole("link", { name: "Agent 1" });
    expect(link).toHaveAttribute("href", `/agents/${AGENT_ID}`);
    // Following the agent does not also open the row's drawer.
    await userEvent.click(link);
    expect(onOpen).not.toHaveBeenCalled();
  });

  it("puts the handle beside a label and prints it as plain text for an approver", async () => {
    renderPage(<RecordTable caption="Records" items={[row({ principal_id: AGENT_ID, label: "triage-bot", kind: "AGENT", number: 1 })]} open={undefined} onOpen={() => undefined} />, APPROVER);
    const table = await screen.findByRole("table", { name: "Records" });
    const [, first] = within(table).getAllByRole("row");
    if (first === undefined) throw new Error("a row expected");
    expect(first).toHaveTextContent("triage-bot Agent 1");
    expect(within(first).getByText("Agent 1")).toHaveClass("faint");
    expect(within(table).queryByRole("link", { name: /triage-bot/ })).toBeNull();
  });

  it("renders a label of markup as the characters it is", async () => {
    renderPage(<RecordTable caption="Records" items={[row({ principal_id: AGENT_ID, label: HOSTILE, kind: "AGENT", number: 2 })]} open={undefined} onOpen={() => undefined} />, ADMIN);
    expect(await screen.findByRole("link", { name: HOSTILE })).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("links a person only for a reader who manages access, and never the scheduler", async () => {
    const person = { principal_id: PERSON_ID, label: null, number: 2, kind: "HUMAN_APPROVER" };
    const first = renderPage(<PrincipalName principal={person} link />, ADMIN);
    expect(await screen.findByRole("link", { name: "User 2" })).toHaveAttribute("href", `/people/${PERSON_ID}`);
    first.unmount();
    const second = renderPage(<PrincipalName principal={person} link />, NARROW);
    expect(await screen.findByText("User 2")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
    second.unmount();
    renderPage(<PrincipalName principal={{ principal_id: PERSON_ID, label: null, number: 1, kind: "SYSTEM" }} link />, ADMIN);
    expect(await screen.findByText("ExecBound scheduler")).toBeInTheDocument();
    expect(screen.queryByRole("link")).toBeNull();
  });
});
