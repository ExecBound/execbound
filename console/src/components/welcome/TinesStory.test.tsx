// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TenantSettingsView } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { isAgentHost, savedAgentHost, saveAgentHost } from "./agent-host";
import { TinesStory } from "./TinesStory";

const CONNECTION = { origin: "https://gateway.example.test", recipes: {}, workstation: null, operation_ref: null, samples_state: "absent" };

function tenant(seconds: number | null): TenantSettingsView {
  return {
    tenant_id: "7f8e9d0c-0000-4000-8000-000000000003",
    tenant_name: "Synthetic SOC",
    mode: { value: "ENFORCE", changed: null },
    deadline: { seconds, bounds: { min: 120, max: 3600 }, changed: null },
    stop: null,
    bundle_id: null,
    monitoring: { sources: 0, reporting: 0, stale: 0, overdue: 0, open_findings: 0 },
    delivery: { window_days: 7, delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null, lapsed: 0, failed: 0 },
    approval_windows: [],
    destinations: [],
  };
}

function serve(seconds: number | null = 600) {
  answerWith({
    "GET /api/console/v1/connection": { body: CONNECTION },
    "GET /api/console/v1/tenant": { body: tenant(seconds) },
  });
}

function steps(): string[] {
  const list = document.querySelector(".tines-steps");
  if (list === null) throw new Error("No steps");
  return [...list.querySelectorAll(":scope > li")].map((item) => item.textContent);
}

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("a Tines story as the agent's host (UX14, #678)", () => {
  it("offers both committed stories as downloads", async () => {
    serve();
    renderPage(<TinesStory />);
    const execute = await screen.findByRole("link", { name: "Download the Execute story" });
    const gate = screen.getByRole("link", { name: "Download the Gate story" });
    expect(execute).toHaveAttribute("download");
    expect(gate).toHaveAttribute("download");
    expect(execute.getAttribute("href")).toMatch(/stories\/tines\/execbound-governed-action\.json$/);
    expect(gate.getAttribute("href")).toMatch(/stories\/tines\/execbound-gate\.json$/);
    expect(screen.getByText("Both are Advisory for Tines: nothing forces a story to call ExecBound.")).toBeInTheDocument();
  });

  it("gives the Execute steps in the README's order, with the origin and the deadline from the server", async () => {
    serve(600);
    renderPage(<TinesStory />);
    expect(await screen.findByRole("region", { name: "execbound_origin" })).toHaveTextContent("https://gateway.example.test");
    expect(await screen.findByText("600")).toBeInTheDocument();
    const order = steps();
    expect(order).toHaveLength(5);
    expect(order[0]).toMatch(/Text credential named exactly execbound holding this agent's API key/);
    expect(order[1]).toMatch(/execbound_origin, execbound_poll_seconds and execbound_wait_seconds/);
    expect(order[2]).toMatch(/Import the story into a real team/);
    expect(order[3]).toMatch(/open the Entry action once in the Tines editor, which assigns its webhook path and secret/);
    expect(order[3]).toMatch(/enable Send to Story with Entry as the entry action and both Outcome and Refused: no reference as exits/);
    expect(order[4]).toMatch(/Run it with a test event naming a target you control, a reference and an incident_id/);
  });

  it("waits the README's 120 seconds where the workspace's deadline is off, and says so", async () => {
    serve(null);
    renderPage(<TinesStory />);
    expect(await screen.findByText("The approval deadline is off in this workspace.", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
  });

  it("gives the Gate steps: three credentials, a dedicated team with its warning, then the way in and the test", async () => {
    serve();
    renderPage(<TinesStory />);
    await userEvent.click(await screen.findByRole("radio", { name: /Gate: your vendor connectors stay in Tines/ }));
    const order = steps();
    expect(order).toHaveLength(6);
    for (const name of ["execbound_gate", "execbound_gate_vendor", "execbound_gate_signing"]) expect(order[0]).toContain(name);
    expect(order[1]).toMatch(/execbound_origin, execbound_vendor_origin, execbound_gate_key_id, execbound_poll_seconds and execbound_wait_seconds/);
    expect(order[2]).toMatch(/dedicated team/);
    expect(order[2]).toMatch(/The signing credential cannot be host-restricted, so any story in the team that can read it can sign with it\./);
    expect(order[3]).toMatch(/An administrator of this deployment registers the story's public key and a Gate account/);
    expect(order[4]).toMatch(/Outcome, Needs administrator and Refused: no reference as exits/);
    expect(order[5]).toMatch(/Run it with a test event/);
  });

  it("names the service operator, not a command, for the Gate where the edition runs none", async () => {
    serve();
    renderPage(withEdition(<TinesStory />, { operatorCommands: false }), { ...PLACEHOLDER, service: { ...NO_SERVICE, support_email: "help@example.com" } });
    await userEvent.click(await screen.findByRole("radio", { name: /Gate/ }));
    const order = steps();
    expect(order[3]).toMatch(/Your service operator registers the story's public key: send them the public key and the actions to gate: help@example\.com\./);
    expect(order[3]).not.toMatch(/administrator of this deployment/);
    const list = document.querySelector<HTMLElement>(".tines-steps");
    if (list === null) throw new Error("No steps");
    expect(within(list).getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
  });
});

describe("the agent host preference", () => {
  it("knows a Tines story and reads a saved one back", () => {
    expect(isAgentHost("tines")).toBe(true);
    saveAgentHost("agent-1", "tines");
    expect(savedAgentHost("agent-1")).toBe("tines");
  });
});
