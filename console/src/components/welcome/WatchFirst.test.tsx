// SPDX-License-Identifier: AGPL-3.0-only
// Watching first where monitoring is connected from the console (MC23, #678). In an edition
// whose readers run no operator commands, the start-by-watching line and the Discover card's
// link appear only once the deployment says a provider can be connected here, and they link
// that provider: Tines where it is available, Microsoft Entra where only it is. Until then the
// line is absent and the card keeps its sentence naming the service operator. Where the edition
// offers operator commands nothing changes, and nothing is read to decide it.

import { screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SampleStatusView } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage, settle, type Seen } from "../../test/page";
import { SETUP, setupView } from "../../test/setup-view";
import { options } from "../../test/source-data";
import { NextStep } from "./NextStep";
import { WelcomePage } from "./WelcomePage";

const SAMPLES = "/api/console/v1/samples";
const CONNECT = "/api/console/v1/monitor/connect";
const ABSENT: SampleStatusView = { state: "absent", offered: false, available: false, demo_available: false, demo_needs_refresh: false, bundle_id: null, hosts: [], observed_at: null, stale_at: null, first_request: null };
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", mode: "ENFORCE", service: { ...NO_SERVICE, support_email: "help@example.com" } };
// What the hosted edition sets: watching first offered, no operator commands.
const SERVICE = { watchFirst: true, operatorCommands: false };
const UNCONFIGURED = options({ tines: "unconfigured", entra: "unconfigured", sources: "unconfigured" });
const ENTRA_ONLY = options({ tines: "unconfigured", sources: "unconfigured", entra: "available", entra_display_name: "Example Scout", entra_client_id: "66666666-7777-8888-9999-aaaaaaaaaaaa" });

afterEach(() => {
  vi.unstubAllGlobals();
});

function serve(connect: ReturnType<typeof options> | null): Seen[] {
  return answerWith({
    [`GET ${SAMPLES}`]: { body: ABSENT },
    [`GET ${SETUP}`]: { body: setupView({ policy: "done" }) },
    "GET /api/console/v1/agents": { body: { agents: [], next: null } },
    ...(connect !== null ? { [`GET ${CONNECT}`]: { body: connect } } : {}),
  });
}

async function connectStep(edition: Parameters<typeof withEdition>[1]) {
  renderPage(withEdition(<WelcomePage step="connect" onStep={() => undefined} />, edition), ADMIN);
  await screen.findByRole("heading", { name: "Connect an agent" });
  await settle();
  await settle();
}

async function discoverCard(edition: Parameters<typeof withEdition>[1]): Promise<HTMLElement> {
  renderPage(withEdition(<WelcomePage step="controls" onStep={() => undefined} />, edition), ADMIN);
  await screen.findByRole("heading", { name: "Discover other activity" });
  await settle();
  await settle();
  const card = screen.getByRole("heading", { name: "Discover other activity" }).closest<HTMLElement>("section");
  if (card === null) throw new Error("No Discover card");
  return card;
}

describe("watching first where the console connects monitoring (MC23)", () => {
  it("offers no line while neither provider can be connected here, and the card names the operator", async () => {
    serve(UNCONFIGURED);
    await connectStep(SERVICE);
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
    const card = await discoverCard(SERVICE);
    expect(card).toHaveTextContent("Monitoring setup in the console comes later here. Ask your service operator to connect a source: help@example.com.");
    expect(card.querySelector('a[href^="/monitor"]')).toBeNull();
  });

  it("links Tines once it can be connected here, on the line and on the card", async () => {
    serve(options());
    await connectStep(SERVICE);
    const line = screen.getByText(/Or start by watching what your Tines stories and Entra agents can already do/);
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
    const card = await discoverCard(SERVICE);
    expect(within(card).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
    expect(card).not.toHaveTextContent(/comes later here/);
  });

  it("links Microsoft Entra where only it can be connected here", async () => {
    serve(ENTRA_ONLY);
    await connectStep(SERVICE);
    const line = screen.getByText(/Or start by watching/);
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=entra_agent_id");
    const card = await discoverCard(SERVICE);
    expect(within(card).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=entra_agent_id");
  });

  it("shows Home's line on the same rule", async () => {
    serve(options());
    renderPage(withEdition(<NextStep />, SERVICE), ADMIN);
    const line = await screen.findByText(/Or start by watching/);
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
  });

  it("changes nothing, and reads nothing to decide it, where the edition offers operator commands", async () => {
    const calls = serve(null);
    await connectStep({ watchFirst: true, operatorCommands: true });
    const line = screen.getByText(/Or start by watching/);
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
    expect(calls.filter((call) => call.path === CONNECT)).toHaveLength(0);
  });

  it("offers nothing where the edition offers no watching first, whatever can be connected", async () => {
    serve(options());
    await connectStep({ watchFirst: false, operatorCommands: false });
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
  });
});
