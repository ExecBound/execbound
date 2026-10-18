// SPDX-License-Identifier: AGPL-3.0-only
import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SampleStatusView, SetupView } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { answerWith, heldReply, renderPage } from "../../test/page";
import { AGENT, CHOOSE_SPACE, SETUP, SPACE, setupView } from "../../test/setup-view";
import { NextStep } from "./NextStep";

const SAMPLES = "/api/console/v1/samples";
const OFFERED: SampleStatusView = { state: "absent", offered: true, available: true, demo_available: false, demo_needs_refresh: false, bundle_id: null, hosts: [], observed_at: null, stale_at: null, first_request: null };
const NOT_OFFERED: SampleStatusView = { ...OFFERED, offered: false };
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", mode: "ENFORCE" };

afterEach(() => {
  vi.unstubAllGlobals();
});

function show(setup: SetupView, samples: SampleStatusView = NOT_OFFERED, session: SessionSummary = ADMIN, edition: Parameters<typeof withEdition>[1] = {}) {
  answerWith({ [`GET ${SETUP}`]: { body: setup }, [`GET ${SAMPLES}`]: { body: samples } });
  renderPage(withEdition(<NextStep />, edition), session);
}

function card() {
  return within(screen.getByRole("heading", { name: /Your (next step|workspace)/ }).closest("section") ?? document.body);
}

async function primary(name: string) {
  return (await screen.findByRole("link", { name })).getAttribute("href");
}

describe("Home's next step from the Space's setup (UX12, #678)", () => {
  it("opens guided setup while the reads are out", async () => {
    const held = heldReply();
    answerWith({ [`GET ${SETUP}`]: () => held.reply, [`GET ${SAMPLES}`]: { body: NOT_OFFERED } });
    renderPage(<NextStep />, ADMIN);
    expect(await screen.findByText("Open guided setup to try an example or connect your agent.")).toBeInTheDocument();
    expect(await primary("Open guided setup")).toBe("/welcome");
  });

  it("asks for a Space where the session looks at all of them, and links nothing", async () => {
    show(CHOOSE_SPACE);
    expect(await screen.findByText("Choose a Space to see what is left to set up in it.")).toBeInTheDocument();
    expect(card().queryByRole("link")).toBeNull();
  });

  it("offers the samples where they can tick something in this Space", async () => {
    show(setupView({}, { connected: false }), OFFERED);
    expect(await screen.findByText(/Try ExecBound on sample targets, or ask your operator to connect a provider\. Requests from agents are refused until this Space has a connection and an active policy\./)).toBeInTheDocument();
    expect(await primary("Add sample targets")).toBe("/welcome?step=example");
  });

  it("gives the operator's row, then says samples go to the default Space, in another Space", async () => {
    show(setupView({}, { connected: false, samples_here: false, default_space_id: SPACE }), OFFERED);
    expect(await screen.findByText(/Connect a provider to this Space first/)).toHaveTextContent(/switch to it in the sidebar to try them\.$/);
    expect(screen.queryByRole("link", { name: "Add sample targets" })).toBeNull();
    expect(await primary("See the operator steps")).toBe("/welcome?step=connect");
  });

  it("gives the operator's row alone to a Space-scoped administrator", async () => {
    show(setupView({}, { connected: false, samples_here: false, default_space_id: null }), OFFERED);
    const text = await screen.findByText(/Connect a provider to this Space first/);
    expect(text).not.toHaveTextContent(/default Space/);
  });

  it("names the service operator where the edition runs no commands", async () => {
    show(setupView({}, { connected: false }), NOT_OFFERED, { ...ADMIN, service: { ...NO_SERVICE, support_email: "help@example.com" } }, { operatorCommands: false, watchFirst: false });
    expect(await screen.findByText(/Your service operator connects providers for this workspace/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
    expect(screen.queryByRole("link", { name: "See the operator steps" })).toBeNull();
  });

  it.each([
    [{}, "Activate a policy in this Space. Until then every request is refused.", "Open policies", "/policy"],
    [{ policy: "done" }, "Connect your first agent in this Space to see how ExecBound controls its actions.", "Open guided setup", "/welcome?step=connect"],
    [{ policy: "done", agent_key: "done" }, "Finish connecting your agent and send it a first request.", "Finish agent setup", `/agents/${AGENT}`],
    [{ policy: "done", agent_key: "done", first_request: "done" }, "Choose who can review the requests your policy holds.", "Choose a reviewer", "/welcome?step=controls"],
    [{ policy: "done", agent_key: "done", first_request: "done", reviewer: "done" }, "Decide a held request in Approvals to see the whole loop.", "Open approvals", "/approvals"],
  ] as const)("words the next step %#", async (states, text, link, href) => {
    show(setupView(states));
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(await primary(link)).toBe(href);
  });

  it("names no label for the agent it links", async () => {
    show(setupView({ policy: "done", agent_key: "done" }));
    expect(await primary("Finish agent setup")).toBe(`/agents/${AGENT}`);
    expect(card().queryByText(/Agent \d/)).toBeNull();
  });

  it("says approvals need Enforcing where the only step left cannot be done while observing", async () => {
    show(
      setupView({ policy: "done", agent_key: "done", first_request: "done", reviewer: "done", first_decision: "needs_enforcing" }, { next: null, observed: { since: "2026-10-01T00:00:00Z", eligible: 0, held: 0, denied: 0 } }),
      NOT_OFFERED,
      { ...ADMIN, mode: "OBSERVE" },
    );
    expect(await screen.findByText(/Approvals need Enforcing\. While this workspace observes, nothing waits for a person\./)).toBeInTheDocument();
    expect(await primary("Change the mode")).toBe("/tenant");
  });

  it("counts what observing would have done, only while observing and with a count", async () => {
    const observed = { since: "2026-10-01T00:00:00Z", eligible: 3, held: 2, denied: 1 };
    show(setupView({ policy: "done", agent_key: "done", first_request: "done", reviewer: "done", first_decision: "needs_enforcing" }, { next: null, observed }), NOT_OFFERED, { ...ADMIN, mode: "OBSERVE" });
    expect(await screen.findByText(/in the last 7 days, 3 requests would have run, 2 would have waited for a person and 1 would have been denied/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review before enforcing" })).toHaveAttribute("href", "/activity?state=OBSERVED&since=7d");
    expect(screen.getAllByRole("link", { name: "Change the mode" })).toHaveLength(1);
  });

  it("leaves the observing line out under Enforcing, and with nothing counted", async () => {
    show(setupView({ policy: "done" }, { observed: { since: "2026-10-01T00:00:00Z", eligible: 3, held: 2, denied: 1 } }), NOT_OFFERED, ADMIN);
    await screen.findByText(/Connect your first agent/);
    expect(screen.queryByText(/would have run/)).toBeNull();
    vi.unstubAllGlobals();
    cleanup();
    show(setupView({ policy: "done" }, { observed: { since: "2026-10-01T00:00:00Z", eligible: 0, held: 0, denied: 0 } }), NOT_OFFERED, { ...ADMIN, mode: "OBSERVE" });
    await screen.findByText(/Connect your first agent/);
    expect(screen.queryByText(/would have run/)).toBeNull();
  });

  it("offers watching first in core while no request has arrived, and never in an edition that cannot", async () => {
    show(setupView({ policy: "done" }));
    const line = await screen.findByText(/Or start by watching/);
    expect(line).toHaveTextContent("Monitoring shows activity; it does not block anything.");
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
  });

  it("offers no watching first once a request has arrived", async () => {
    show(setupView({ policy: "done", agent_key: "done", first_request: "done" }));
    await screen.findByText(/Choose who can review/);
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
  });

  it("offers no watching first in the hosted edition", async () => {
    show(setupView({ policy: "done" }), NOT_OFFERED, ADMIN, { watchFirst: false });
    await screen.findByText(/Connect your first agent/);
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
  });

  it("says the workspace is set up once nothing is left", async () => {
    show(setupView({ policy: "done", agent_key: "done", first_request: "done", reviewer: "done", first_decision: "done" }));
    expect(await screen.findByRole("heading", { name: "Your workspace" })).toBeInTheDocument();
    expect(screen.getByText("Review your controls, connect another agent, or add teammates who can review requests.")).toBeInTheDocument();
  });
});
