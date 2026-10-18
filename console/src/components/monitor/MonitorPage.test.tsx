// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearToasts } from "../../lib/toast";
import { renderMonitor } from "../../test/monitor";
import {
  AGENT,
  agentDetail,
  agents,
  CONNECTION,
  connection,
  FINDING,
  PRINCIPAL,
  snapshot,
  story,
} from "../../test/monitor-data";
import { answerWith, renderPage } from "../../test/page";
import { TENANT_STALE_MS } from "../../shell/counts";
import { AgentDetailPage } from "./AgentDetailPage";
import { accountable } from "./Agents";
import { reportCommand } from "./Inventory";
import { MonitorPage, TABS_STALE_MS } from "./MonitorPage";
import { parseMonitorSearch } from "./search";

const SNAPSHOT = "GET /api/console/v1/monitor";
const TENANT = "GET /api/console/v1/tenant";
const scrolled = vi.fn();

beforeEach(() => {
  scrolled.mockReset();
  Element.prototype.scrollIntoView = scrolled;
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

function tenant(open: number, stale: number, overdue: number) {
  return { body: { monitoring: { sources: 1, reporting: 0, stale, overdue, open_findings: open } } };
}

function badgeOf(card: HTMLElement): HTMLElement {
  const badge = card.querySelector<HTMLElement>(".badge");
  if (badge === null) throw new Error("No badge");
  return badge;
}

async function card(title: string): Promise<HTMLElement> {
  const found = (await screen.findByRole("heading", { name: title })).closest("section");
  if (found === null) throw new Error(`No card ${title}`);
  return found;
}

describe("the monitoring page", () => {
  it("shows the connections view by default and names every view in the tab strip", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot() } });
    renderMonitor("/monitor");
    expect(await screen.findByText("Synthetic <b>Tines</b> tenant")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Monitoring");
    const tabs = screen.getByRole("navigation", { name: "Monitoring views" });
    expect(within(tabs).getAllByRole("link").map((link) => link.textContent)).toEqual([
      "Connections",
      "Inventory",
      "Agents",
      "External activity",
      "Findings",
      "Alert settings",
    ]);
    expect(within(tabs).getByRole("link", { name: "Connections" })).toHaveAttribute("aria-current", "page");
    expect(within(tabs).getByRole("link", { name: "Findings" })).toHaveAttribute("href", "/monitor?view=findings");
    expect(screen.getByText("stories")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("No sources registered")).toBeInTheDocument();
  });

  it("counts open findings and quiet items on their tabs (MQ3)", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot() }, [TENANT]: tenant(3, 1, 1) });
    renderMonitor("/monitor");
    const tabs = await screen.findByRole("navigation", { name: "Monitoring views" });
    expect(await within(tabs).findByRole("link", { name: "Findings, 3 open" })).toHaveAttribute("href", "/monitor?view=findings");
    expect(within(tabs).getByRole("link", { name: "Connections, 2 quiet" })).toBeInTheDocument();
  });

  it("reads the tenant view with the shell's own freshness, so the two never ask twice", () => {
    expect(TABS_STALE_MS).toBe(TENANT_STALE_MS);
  });

  it("leaves the tabs bare when nothing is open or quiet (MQ3)", async () => {
    const seen = answerWith({ [SNAPSHOT]: { body: snapshot() }, [TENANT]: tenant(0, 0, 0) });
    renderMonitor("/monitor");
    await waitFor(() => {
      expect(seen.some((request) => request.path === "/api/console/v1/tenant")).toBe(true);
    });
    const tabs = screen.getByRole("navigation", { name: "Monitoring views" });
    expect(within(tabs).getByRole("link", { name: "Findings" })).toBeInTheDocument();
    expect(within(tabs).getByRole("link", { name: "Connections" })).toBeInTheDocument();
  });

  it("lists agents with the denominator in words, a hostile name as text, and no nobody for a refused read", async () => {
    answerWith({ "GET /api/console/v1/monitor/agents": { body: agents } });
    renderMonitor("/monitor?view=agents");
    expect(await screen.findByText('<script>alert("x")</script> payroll')).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
    expect(screen.getByText(/counts agents this connection could enumerate, not the agents that exist/)).toBeInTheDocument();
    expect(screen.getByText("Agent identity")).toBeInTheDocument();
    expect(screen.getByText("Could not read")).toBeInTheDocument();
    expect(screen.getByText("1 grant we cannot explain")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /payroll/ })).toHaveAttribute("href", `/monitor/agents/${AGENT}`);
    expect(accountable({ sponsor_state: "absent", sponsor_count: 0, identity_class: "service_principal", owner_count: 2 })).toBe("2 owners");
    expect(accountable({ sponsor_state: "absent", sponsor_count: 0, identity_class: "agent_identity", owner_count: 2 })).toBe("Nobody");
    expect(accountable({ sponsor_state: "present", sponsor_count: 1, identity_class: "agent_identity", owner_count: null })).toBe("1 sponsor");
  });

  it("offers Govern on an unlinked agent with reach, and links a linked one to its agent (MQ9)", async () => {
    const [first] = agents.agents;
    if (first === undefined) throw new Error("fixture");
    const linked = { ...first, agent_id: "aaaaaaaa-0000-4000-8000-000000000002", display_name: "Linked one", linked_principal_id: PRINCIPAL };
    const quiet = { ...first, agent_id: "aaaaaaaa-0000-4000-8000-000000000003", display_name: "No reach", consequential: 0 };
    answerWith({ "GET /api/console/v1/monitor/agents": { body: { ...agents, agents: [first, linked, quiet] } } });
    renderMonitor("/monitor?view=agents");
    expect(await screen.findByRole("link", { name: "Govern" })).toHaveAttribute("href", `/agents/${AGENT}`);
    expect(screen.getByRole("link", { name: "Linked" })).toHaveAttribute("href", `/agents/${PRINCIPAL}`);
    const row = screen.getByText("No reach").closest("tr");
    if (row === null) throw new Error("No row");
    expect(within(row).getByText("No principal linked")).toBeInTheDocument();
  });

  it("shows inventory as metadata", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot() } });
    renderMonitor("/monitor?view=inventory");
    expect(await screen.findByText("Phishing triage")).toBeInTheDocument();
    expect(screen.getByText("Instrumented")).toBeInTheDocument();
    expect(screen.getByText("okta_api")).toBeInTheDocument();
    expect(screen.getByText("No expiry recorded")).toBeInTheDocument();
  });
});

describe("collection freshness on Connections (MQ7, MQ11)", () => {
  it("takes the allow tone only for a reporting connection, and says when one is overdue", async () => {
    answerWith({
      [SNAPSHOT]: {
        body: snapshot({
          connections: [
            connection({ connection_id: "c1", label: "Reporting one" }),
            connection({ connection_id: "c2", label: "Stopped one", reporting: false, overdue_since: "2026-09-19T05:01:00+00:00" }),
            connection({ connection_id: "c3", label: "Backlogged one", reporting: false, last_outcome: "BACKLOG" }),
            connection({ connection_id: "c4", label: "Failing one", reporting: false, health_state: "ERROR", overdue_since: "2026-09-19T05:01:00+00:00" }),
          ],
        }),
      },
    });
    renderMonitor("/monitor");
    const reporting = await card("Reporting one");
    expect(badgeOf(reporting)).toHaveTextContent("Collecting");
    expect(badgeOf(reporting)).toHaveClass("badge-allow");
    const stopped = await card("Stopped one");
    expect(badgeOf(stopped)).toHaveTextContent("Collection overdue");
    expect(badgeOf(stopped)).not.toHaveClass("badge-allow");
    expect(within(stopped).getByText("Overdue since")).toBeInTheDocument();
    expect(within(stopped).getByText(/A schedule that stopped and a collector that can no longer sign in both look like this/)).toBeInTheDocument();
    const backlogged = await card("Backlogged one");
    expect(badgeOf(backlogged)).toHaveTextContent("Collecting");
    expect(badgeOf(backlogged)).toHaveClass("badge-hold");
    expect(within(backlogged).getByText(/The last run did not complete, or a permission the collector needs is not available/)).toBeInTheDocument();
    const failing = await card("Failing one");
    expect(badgeOf(failing)).toHaveTextContent("Error");
    expect(within(failing).getByText("Overdue since")).toBeInTheDocument();
    expect(document.querySelectorAll(".badge-allow")).toHaveLength(1);
  });

  it("puts quiet items first, then what needs attention, then the rest", async () => {
    const source = (id: string, label: string, health: string, coverage: string) => ({
      source_id: id,
      label,
      story_id: "4001",
      coverage,
      health_state: health,
      health_changed_at: null,
      last_event_at: null,
      last_heartbeat_at: null,
      heartbeat_seconds: 300,
      expires_at: "2026-09-20T05:00:00+00:00",
      previous_valid_until: null,
      revoked_at: null,
      last_refusal_code: null,
      accepted_count: 0,
      administered: true,
    });
    answerWith({
      [SNAPSHOT]: {
        body: snapshot({
          connections: [
            connection({ connection_id: "c1", label: "Healthy" }),
            connection({ connection_id: "c2", label: "Not reporting", reporting: false }),
            connection({ connection_id: "c3", label: "Quiet", reporting: false, overdue_since: "2026-09-19T05:01:00+00:00" }),
          ],
          sources: [
            source("s1", "Reporting source", "REPORTING", "Reporting"),
            source("s2", "Expired source", "NEVER_SEEN", "Expired"),
            source("s3", "Stale source", "STALE", "Stale"),
          ],
        }),
      },
    });
    renderMonitor("/monitor?focus=quiet");
    await card("Healthy");
    const titles = screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent);
    expect(titles.filter((title) => title !== "Connect monitoring")).toEqual([
      "Quiet",
      "Not reporting",
      "Healthy",
      "Stale source",
      "Expired source",
      "Reporting source",
    ]);
    const marked = document.querySelectorAll(".monitor-marked");
    expect(marked).toHaveLength(1);
    expect(marked[0]).toBe(await card("Quiet"));
    await waitFor(() => {
      expect(scrolled).toHaveBeenCalled();
    });
  });

  it("says nothing is quiet when the link's quiet item has gone, and marks nothing", async () => {
    answerWith({
      [SNAPSHOT]: { body: snapshot({ connections: [connection({ label: "Not reporting", reporting: false })] }) },
    });
    renderMonitor("/monitor?focus=quiet");
    expect(await screen.findByText("Nothing is quiet now.")).toBeInTheDocument();
    expect(document.querySelector(".monitor-marked")).toBeNull();
  });
});

describe("governing from the Monitoring agent page (MQ9)", () => {
  it("links an unlinked agent to its agent page to govern or bind, and keeps the operator commands folded", async () => {
    answerWith({ [`GET /api/console/v1/monitor/agents/${AGENT}`]: { body: agentDetail() } });
    renderPage(<AgentDetailPage agentId={AGENT} />);
    const govern = await screen.findByRole("link", { name: "Govern this agent" });
    expect(govern).toHaveAttribute("href", `/agents/${AGENT}`);
    expect(screen.getByRole("link", { name: "Bind to an existing agent" })).toHaveAttribute("href", `/agents/${AGENT}`);
    expect(screen.getByText(/Governing creates an ExecBound agent for this directory agent/)).toBeInTheDocument();
    const commands = screen.getByText("Operator commands").closest("details");
    if (commands === null) throw new Error("No operator commands");
    expect(commands).not.toHaveAttribute("open");
    expect(commands).toHaveTextContent("monitor link-agent");
    expect(commands).toHaveTextContent("monitor accept-reach");
    expect(screen.getByRole("link", { name: "Ungoverned reach" })).toHaveAttribute(
      "href",
      `/monitor?view=findings&state=all&open=${FINDING}`,
    );
  });

  it("opens a linked agent's governing agent, named by its number", async () => {
    answerWith({
      [`GET /api/console/v1/monitor/agents/${AGENT}`]: {
        body: agentDetail({
          linked_principal_id: PRINCIPAL,
          linked_principal_ref: { principal_id: PRINCIPAL, kind: "AGENT", label: null, number: 3 },
        }),
      },
    });
    renderPage(<AgentDetailPage agentId={AGENT} />, { ...(await import("../../test/monitor")).ADMIN });
    expect(await screen.findByRole("link", { name: "Open the governed agent" })).toHaveAttribute("href", `/agents/${PRINCIPAL}`);
    expect(screen.getByRole("link", { name: "Agent 3" })).toHaveAttribute("href", `/agents/${PRINCIPAL}`);
    expect(screen.queryByRole("link", { name: "Govern this agent" })).toBeNull();
  });
});

describe("cross-links between Monitoring's rows (MQ10, MQ11)", () => {
  it("links a valid story to Inventory and an observation to its findings", async () => {
    const observation = {
      observation_id: "0b0b0b0b-0000-4000-8000-000000000004",
      occurred_at: "2026-09-19T05:00:00+00:00",
      received_at: "2026-09-19T05:00:00+00:00",
      kind: "tool_result",
      story_id: "4001",
      action: "identity.disable",
      evidence: "reported",
      operation_name: null,
      actor_ref: null,
      target_ref: "u-1",
      outcome: "success",
      evaluation_state: "COMPLETED",
      evaluation_result: "MATCH",
      integrity_conflict_at: null,
      finding_ids: [FINDING],
    };
    answerWith({
      [SNAPSHOT]: {
        body: snapshot({
          observations: [
            observation,
            { ...observation, observation_id: "0b0b0b0b-0000-4000-8000-000000000005", story_id: "a b", finding_ids: [FINDING, CONNECTION] },
            { ...observation, observation_id: "0b0b0b0b-0000-4000-8000-000000000006", story_id: "4002", finding_ids: [] },
          ],
        }),
      },
    });
    renderMonitor("/monitor?view=activity");
    // The router writes a digit-only id quoted, so it reads back as the same string.
    expect(await screen.findByRole("link", { name: "4001" })).toHaveAttribute("href", "/monitor?view=inventory&story=%224001%22");
    expect(screen.getByText("a b")).not.toHaveAttribute("href");
    expect(screen.queryByRole("link", { name: "a b" })).toBeNull();
    expect(screen.getByRole("link", { name: "Open finding" })).toHaveAttribute("href", `/monitor?view=findings&state=all&open=${FINDING}`);
    expect(screen.getByRole("link", { name: "Open findings (2)" })).toHaveAttribute("href", `/monitor?view=findings&state=all&open=${FINDING}`);
    expect(screen.getAllByRole("link", { name: /Open finding/ })).toHaveLength(2);
  });

  it("marks the story the address names, and says when it is not shown", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot({ stories: [story(), story({ external_id: "4002", name: "Other" })] }) } });
    renderMonitor("/monitor?view=inventory&story=%224001%22");
    const row = (await screen.findByText("Phishing triage")).closest("tr");
    expect(row).toHaveAttribute("aria-current", "true");
    await waitFor(() => {
      expect(scrolled).toHaveBeenCalled();
    });
    expect(screen.queryByText("This story is not in the discovered inventory shown here.")).toBeNull();
  });

  it("says a story the address names is not shown, and marks no row", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot() } });
    renderMonitor("/monitor?view=inventory&story=%229999%22");
    expect(await screen.findByText("This story is not in the discovered inventory shown here.")).toBeInTheDocument();
    expect(document.querySelector("[aria-current='true']")).toBeNull();
  });

  it("offers the command to report a gap story only for an id the command accepts", async () => {
    const gap = (external_id: string) => story({ external_id, name: `Gap ${external_id}`, source_id: null, gap_opened_at: "2026-09-19T05:00:00+00:00" });
    answerWith({
      [SNAPSHOT]: { body: snapshot({ stories: [gap("4001"), gap("4001; rm -rf /"), gap("-rf"), gap("9".repeat(91))] }) },
    });
    renderMonitor("/monitor?view=inventory");
    const buttons = await screen.findAllByRole("button", { name: "Show the command to report this story" });
    expect(buttons).toHaveLength(1);
    const [button] = buttons;
    if (button === undefined) throw new Error("No button");
    await userEvent.click(button);
    expect(screen.getByLabelText("Report command")).toHaveTextContent(
      'uv run python -m execbound.monitoring.commands create-source --credential-file local-data/admin-token.txt --label="Story 4001" --story-id=4001 --hours 24 --output local-data/source-4001.json',
    );
    expect(screen.getByText(/The token this writes expires after 24 hours/)).toBeInTheDocument();
    expect(screen.getByText(/It does not govern them/)).toBeInTheDocument();
    expect(reportCommand("4001; rm -rf /")).toBeNull();
    expect(reportCommand("-rf")).toBeNull();
    expect(reportCommand("9".repeat(91))).toBeNull();
    expect(reportCommand("9".repeat(90))).not.toBeNull();
  });
});

describe("monitoring setup by address (UX18, #678)", () => {
  const EMPTY = { connections: [], sources: [], stories: [], credentials: [], observations: [], findings: [], deliveries: [], profile: null, open_findings: 0 };

  it.each([
    ["tines", "tines"],
    ["entra_agent_id", "entra_agent_id"],
  ])("opens setup with %s chosen from ?setup=", async (setup, value) => {
    answerWith({ [SNAPSHOT]: { body: EMPTY } });
    renderMonitor(`/monitor?setup=${setup}`);
    const dialog = await screen.findByRole("dialog", { name: "Connect a source" });
    expect(within(dialog).getByRole("combobox", { name: "Provider" })).toHaveValue(value);
  });

  it.each(["/monitor?setup=other", "/monitor?setup=Tines", "/monitor?setup=tines&view=findings", "/monitor?setup=tines&view=inventory"])(
    "opens nothing from %s",
    async (path) => {
      answerWith({ [SNAPSHOT]: { body: EMPTY }, "GET /api/console/v1/monitor/findings": { body: { items: [], next: null } } });
      renderMonitor(path);
      await screen.findByRole("heading", { name: "Monitoring" });
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(screen.queryByRole("dialog")).toBeNull();
    },
  );

  it("opens nothing for a setup value handed to the page unchecked", async () => {
    answerWith({ [SNAPSHOT]: { body: EMPTY } });
    renderPage(<MonitorPage {...parseMonitorSearch({ setup: "<script>" })} />);
    expect(await screen.findByRole("heading", { name: "Connect monitoring" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("takes setup out of the address, as a replacement, when the dialog closes", async () => {
    answerWith({ [SNAPSHOT]: { body: EMPTY } });
    const { router } = renderMonitor("/monitor?setup=tines");
    const before = router.history.length;
    const dialog = await screen.findByRole("dialog", { name: "Connect a source" });
    await userEvent.click(within(dialog).getByRole("button", { name: /Close/ }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({});
    });
    expect(router.history.length).toBe(before);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows the four figures only once a connection or a source exists", async () => {
    answerWith({ [SNAPSHOT]: { body: EMPTY } });
    const empty = renderMonitor("/monitor");
    expect(await screen.findByText("No collection connection registered")).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "What is shown" }) ?? document.querySelector('[aria-label="What is shown"]')).toBeNull();
    empty.unmount();
    answerWith({ [SNAPSHOT]: { body: snapshot() } });
    renderMonitor("/monitor");
    await screen.findByText("Synthetic <b>Tines</b> tenant");
    expect(document.querySelector('[aria-label="What is shown"]')).not.toBeNull();
  });
});
