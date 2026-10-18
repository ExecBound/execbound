// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readAgentOptions } from "../../api/@tanstack/react-query.gen";
import type { AgentDetail, RecentRow } from "../../api/types.gen";
import { useEdition } from "../../edition/context";
import { POLL_MS } from "../../lib/poll";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage, type Reply, settle } from "../../test/page";
import { AgentConnection } from "./AgentConnection";
import { FirstRequest, LISTEN_MS } from "./FirstRequest";

const AGENT = "22222222-2222-4222-8222-222222222222";
const PATH = `/api/console/v1/agents/${AGENT}`;
const EXECUTION = "99999999-9999-4999-8999-999999999999";

function detail(changes: Partial<AgentDetail> = {}): AgentDetail {
  return {
    row_id: AGENT,
    kind: "principal",
    agent: { principal_id: AGENT, active: true, dormant: false, label: "Triage bot", number: 2, created_at: "2026-09-10T08:00:00Z", deactivated_at: null },
    binding: null,
    discovered: null,
    credentials: [{ credential_id: "33333333-3333-4333-8333-333333333333", issued_at: "2026-09-19T08:00:00Z", expires_at: "2099-09-19T16:00:00Z", revoked_at: null, state: "live", failures: 0 }],
    recent: [],
    runs: [],
    more_runs: false,
    groups: [],
    requests: 0,
    month: "2026-09-01T00:00:00Z",
    bundle: true,
    observe: false,
    limits: [],
    reach: [],
    rules_bundle_id: null,
    options: [],
    ...changes,
  };
}

function recent(state: string): RecentRow {
  return { execution_id: EXECUTION, action: "endpoint.isolate", label: "Isolate endpoint", canonical_target_id: null, state, created_at: "2026-10-08T09:30:00Z", request_ref: "EB-12" };
}

/** The agent's page as the route reads it: the detail from the cache, which the panel's poll refreshes. */
function Page() {
  const data = useQuery(readAgentOptions({ path: { row_id: AGENT } })).data;
  return data === undefined ? null : <FirstRequest detail={data} />;
}

let visibility: DocumentVisibilityState = "visible";

function show(state: DocumentVisibilityState) {
  visibility = state;
  document.dispatchEvent(new Event("visibilitychange"));
}

beforeEach(() => {
  visibility = "visible";
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => visibility });
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
});

afterEach(() => {
  show("visible");
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function asked(seen: { method: string; path: string }[]): number {
  return seen.filter((request) => request.method === "GET" && request.path === PATH).length;
}

async function tick(ms: number) {
  await act(async () => {
    vi.advanceTimersByTime(ms);
    await Promise.resolve();
  });
  await settle();
}

describe("waiting for an agent's first request (UX13, #678)", () => {
  it("says it is waiting, in a status region, and asks again on the shared timer", async () => {
    const seen = answerWith({ [`GET ${PATH}`]: { body: detail() } });
    renderPage(<Page />);
    const status = await screen.findByText("Waiting for the first request from Triage bot…");
    expect(status.closest('[role="status"]')).not.toBeNull();
    const before = asked(seen);
    await tick(POLL_MS);
    await waitFor(() => {
      expect(asked(seen)).toBe(before + 1);
    });
  });

  it("asks nothing while the tab is hidden", async () => {
    const seen = answerWith({ [`GET ${PATH}`]: { body: detail() } });
    renderPage(<Page />);
    await screen.findByText(/Waiting for the first request/);
    const before = asked(seen);
    show("hidden");
    await tick(POLL_MS * 3);
    expect(asked(seen)).toBe(before);
  });

  it("names the agent as text, whatever its label holds", async () => {
    const label = "<img src=x onerror=alert(1)>";
    const base = detail();
    answerWith({ [`GET ${PATH}`]: { body: { ...base, agent: { ...base.agent, label } } } });
    const { container } = renderPage(<Page />);
    expect(await screen.findByText(`Waiting for the first request from ${label}…`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("stops ten minutes of wall-clock time after it started, hidden time included, and resumes", async () => {
    const seen = answerWith({ [`GET ${PATH}`]: { body: detail() } });
    renderPage(<Page />);
    await screen.findByText(/Waiting for the first request/);
    show("hidden");
    await tick(9 * 60_000);
    show("visible");
    await tick(60_000);
    expect(await screen.findByText(/Stopped listening after 10 minutes\./)).toBeInTheDocument();
    const stopped = asked(seen);
    await tick(POLL_MS * 3);
    expect(asked(seen)).toBe(stopped);
    await userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) }).click(screen.getByRole("button", { name: "Resume" }));
    expect(await screen.findByText(/Waiting for the first request/)).toBeInTheDocument();
    await tick(POLL_MS);
    // Resuming reads the agent at once and then on the timer again.
    await waitFor(() => {
      expect(asked(seen)).toBeGreaterThan(stopped);
    });
    expect(LISTEN_MS).toBe(10 * 60_000);
  });

  it("shows the request that arrived, its reference and a link to the record", async () => {
    let arrived = false;
    answerWith({ [`GET ${PATH}`]: (): Reply => ({ body: detail({ recent: arrived ? [recent("EXECUTED")] : [] }) }) });
    renderPage(<Page />);
    await screen.findByText(/Waiting for the first request/);
    arrived = true;
    await tick(POLL_MS);
    const open = await screen.findByRole("link", { name: "Open this decision" });
    expect(open).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
    expect(screen.getByText("EB-12")).toBeInTheDocument();
    expect(screen.getByText("executed")).toBeInTheDocument();
    expect(screen.queryByText(/Waiting for the first request/)).toBeNull();
    expect(screen.queryByRole("link", { name: "Approvals" })).toBeNull();
  });

  it("sends a held first request to the Approvals queue, never to one approval", async () => {
    answerWith({ [`GET ${PATH}`]: { body: detail({ recent: [recent("PENDING_APPROVAL")] }) } });
    renderPage(<Page />);
    expect(await screen.findByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals");
    expect(screen.getByText(/It waits for a reviewer in/)).toBeInTheDocument();
  });

  it("names no cause, only the one sentence about refusals before authentication", async () => {
    answerWith({ [`GET ${PATH}`]: { body: detail() } });
    const { container } = renderPage(<Page />);
    await screen.findByText(/Waiting for the first request/);
    const panel = container.querySelector(".first-request");
    expect(panel?.textContent).toBe(
      "Waiting for the first request from Triage bot…Nothing recorded yet. Check the server URL and key in your host. A request refused before authentication leaves no record here.",
    );
  });

  it("says nothing for an agent with no live key", async () => {
    answerWith({ [`GET ${PATH}`]: { body: detail({ credentials: [] }) } });
    const { container } = renderPage(<Page />);
    await settle();
    expect(container.querySelector(".first-request")).toBeNull();
  });
});

describe("Check connection (#678)", () => {
  it("still asks once and counts no event, though the edition's event slot is wired", async () => {
    vi.useRealTimers();
    const seen = answerWith({
      [`GET ${PATH}`]: { body: detail({ recent: [recent("EXECUTED")] }) },
      "GET /api/console/v1/connection": { body: { origin: "http://console.test", recipes: {}, workstation: null, operation_ref: null, samples_state: "absent" } },
    });
    const event = vi.fn();
    function Mounted() {
      const data = useQuery(readAgentOptions({ path: { row_id: AGENT } })).data;
      return data === undefined ? null : <AgentConnection detail={data} />;
    }
    /** Proves the spy would see a call made through the same provider. */
    function Probe() {
      const { event: count } = useEdition();
      return <button type="button" onClick={() => { count("approval_completed"); }}>Probe</button>;
    }
    renderPage(withEdition(<><Mounted /><Probe /></>, { event }));
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    // The refetch settles, then the button reads "Check connection" again, which happens only
    // after the check has been recorded as done; then any effect of that render has run.
    await waitFor(() => {
      expect(asked(seen)).toBe(2);
    });
    await screen.findByRole("button", { name: "Check connection" });
    await settle();
    expect(event).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Probe" }));
    expect(event).toHaveBeenCalledTimes(1);
    expect(event).toHaveBeenCalledWith("approval_completed");
  });
});

describe("choosing a Tines story as the host (UX14, #678)", () => {
  it("replaces the recipe with the two story downloads", async () => {
    vi.useRealTimers();
    answerWith({
      [`GET ${PATH}`]: { body: detail() },
      "GET /api/console/v1/connection": { body: { origin: "http://console.test", recipes: {}, workstation: null, operation_ref: null, samples_state: "absent" } },
    });
    function Mounted() {
      const data = useQuery(readAgentOptions({ path: { row_id: AGENT } })).data;
      return data === undefined ? null : <AgentConnection detail={data} />;
    }
    renderPage(<Mounted />);
    await userEvent.selectOptions(await screen.findByLabelText("Agent host"), "tines");
    expect(await screen.findByRole("link", { name: "Download the Execute story" })).toHaveAttribute("download");
    expect(screen.getByRole("link", { name: "Download the Gate story" })).toHaveAttribute("download");
    expect(screen.queryByRole("region", { name: "Agent configuration" })).toBeNull();
  });
});

describe("the host caveats (UX17, #678)", () => {
  it("keeps the host notes behind About hosts", async () => {
    vi.useRealTimers();
    answerWith({
      [`GET ${PATH}`]: { body: detail() },
      "GET /api/console/v1/connection": { body: { origin: "http://console.test", recipes: {}, workstation: null, operation_ref: null, samples_state: "absent" } },
    });
    function Mounted() {
      const data = useQuery(readAgentOptions({ path: { row_id: AGENT } })).data;
      return data === undefined ? null : <AgentConnection detail={data} />;
    }
    renderPage(<Mounted />);
    const saved = await screen.findByText("Host preference is saved only in this browser. It does not grant access or identify the agent.");
    const oauth = screen.getByText("Claude Desktop and claude.ai require OAuth; that connection method is not available here yet.");
    expect(saved).not.toBeVisible();
    expect(oauth).not.toBeVisible();
    await userEvent.click(screen.getByText("About hosts"));
    expect(saved).toBeVisible();
    expect(oauth).toBeVisible();
  });
});
