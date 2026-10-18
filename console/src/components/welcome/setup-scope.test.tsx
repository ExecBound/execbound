// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";

import { calledWith, serve } from "../../test/api";
import { renderPage } from "../../test/page";
import { AGENT, SETUP, setupView } from "../../test/setup-view";
import { parseAgentsSearch } from "../directory/AgentsList";
import { NextStep } from "./NextStep";
import { WelcomePage } from "./WelcomePage";

const API = "/api/console/v1/agents";
const welcome = {
  slot: null,
  origin: "https://gateway.synthetic.invalid",
  recipes: {},
  hosts: [],
  samples: { state: "absent", offered: false, available: false, bundle_id: null, hosts: [], observed_at: null, stale_at: null, first_request: null },
};
const agent = {
  row_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  principal_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  population: "bound",
  name: "Endpoint responder",
  live: 1,
  last_request: null,
};

afterEach(() => { vi.unstubAllGlobals(); });

it("words the next step from the selected Space's setup read, not the workspace's agents (#678)", async () => {
  const calls = serve({
    [SETUP]: setupView({ policy: "done" }),
    "/api/console/v1/samples": welcome.samples,
    [API]: { agents: [agent], next: null, line: { principals: 12 } },
  });
  renderPage(<NextStep />);
  expect(await screen.findByText(/Connect your first agent in this Space/)).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Finish agent setup" })).toBeNull();
  expect(calls.some((call) => call.path === SETUP)).toBe(true);
  expect(calls.some((call) => call.path === API)).toBe(false);
});

it("links the agent whose key the read names to finish its first request (#678)", async () => {
  serve({ [SETUP]: setupView({ policy: "done", agent_key: "done" }), "/api/console/v1/samples": welcome.samples });
  renderPage(<NextStep />);
  expect(await screen.findByText("Finish connecting your agent and send it a first request.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Finish agent setup" })).toHaveAttribute("href", `/agents/${AGENT}`);
});

it.each(["Connect an agent", "Verify protection"])("shows a scoped empty state in %s despite agents in other Spaces", async (step) => {
  const calls = serve({
    "/api/console/v1/samples": welcome.samples,
    [API]: { agents: [], next: null, line: { principals: 12 } },
  });
  renderPage(<WelcomePage />);
  await userEvent.click(await screen.findByRole("button", { name: new RegExp(`\\d.*${step}`) }));
  expect(await screen.findByText(/No active agent is configured in this Space yet/)).toBeInTheDocument();
  expect(calledWith(calls, "GET", API, { population: "registered" })).toBe(true);
});

it.each(["Connect an agent", "Verify protection"])("makes later registered agents reachable from %s", async (step) => {
  const calls = serve({
    "/api/console/v1/samples": welcome.samples,
    [API]: { agents: [agent], next: "next-page", line: { principals: 60 } },
  });
  renderPage(<WelcomePage />);
  await userEvent.click(await screen.findByRole("button", { name: new RegExp(`\\d.*${step}`) }));
  expect(await screen.findByRole("link", { name: "Endpoint responder" })).toHaveAttribute("href", `/agents/${agent.row_id}?section=connection`);
  expect(screen.getByText(/first page of registered agents in this Space/)).toBeInTheDocument();
  const all = screen.getByRole("link", { name: "View all registered agents" });
  const next = screen.getByRole("link", { name: "Next registered agents" });
  const allSearch = new URL(all.getAttribute("href") ?? "", "http://console.test").searchParams;
  const nextSearch = new URL(next.getAttribute("href") ?? "", "http://console.test").searchParams;
  expect(allSearch.get("population")).toBe("registered");
  expect(allSearch.has("cursor")).toBe(false);
  expect(parseAgentsSearch(Object.fromEntries(nextSearch))).toMatchObject({ population: "registered", cursor: "next-page" });
  expect(calledWith(calls, "GET", API, { population: "registered" })).toBe(true);
});
