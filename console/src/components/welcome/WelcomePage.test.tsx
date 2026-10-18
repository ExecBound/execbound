// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readConnectionOptions } from "../../api/@tanstack/react-query.gen";
import type { ConnectionView, SampleHostView, SampleStatusView } from "../../api/types.gen";
import { forgetServerTime } from "../../lib/clock";
import { NO_SERVICE, PLACEHOLDER } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { dateTime } from "../../lib/words";
import { holdWorkspace, resetWorkspace } from "../../lib/workspace-context";
import { withEdition } from "../../test/edition";
import { answerWith, heldReply, renderPage } from "../../test/page";
import { AT, CHOOSE_SPACE, DECIDED, EXECUTION, POLICY, SETUP, setupView } from "../../test/setup-view";
import { WelcomePage } from "./WelcomePage";

const BUNDLE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SAMPLES = "/api/console/v1/samples";

const ABSENT: SampleStatusView = {
  state: "absent",
  offered: false,
  available: true,
  demo_available: false,
  demo_needs_refresh: false,
  bundle_id: null,
  hosts: [],
  observed_at: null,
  stale_at: null,
  first_request: null,
};

function sampleHost(provider_id: string, hostname: string, role: string, environment: string, criticality: number, effect: string, incident: number): SampleHostView {
  return { provider_id, hostname, role, environment, criticality, incident_id: `22222222-0000-4000-8000-00000000000${String(incident)}`, effect, rules: [] };
}

const PRESENT: SampleStatusView = {
  state: "removable",
  offered: false,
  available: true,
  demo_available: true,
  demo_needs_refresh: false,
  bundle_id: BUNDLE,
  hosts: [
    sampleHost("sample-dc-01", "dc-01.sample.invalid", "domain_controller", "production", 3, "deny", 3),
    sampleHost("sample-ws-dev-01", "ws-dev-01.sample.invalid", "workstation", "development", 1, "allow", 1),
    sampleHost("sample-ws-prod-01", "ws-prod-01.sample.invalid", "workstation", "production", 2, "require approval", 2),
  ],
  observed_at: "2026-09-24T10:00:00+00:00",
  stale_at: "2026-09-24T11:00:00+00:00",
  first_request: null,
};

const FRESH_UNTIL = "2099-09-24T11:00:00+00:00";

const REFRESHED: SampleStatusView = {
  ...PRESENT,
  observed_at: "2099-09-24T10:00:00+00:00",
  stale_at: FRESH_UNTIL,
  hosts: PRESENT.hosts.map((host) => ({ ...host, incident_id: (host.incident_id ?? "").replace("22222222", "33333333") })),
};

const CONNECTION = "/api/console/v1/connection";

const CONNECTED: ConnectionView = { operation_ref: null, origin: "http://console.test", recipes: {}, samples_state: "removable", workstation: null };

/** The connection card's read, mounted beside the page so a test can see it asked again. */
function ConnectionRead() {
  useQuery(readConnectionOptions());
  return null;
}

/**
 * Holds the samples' first read after a change until released, so a test can look at the card
 * between the server's answer to the change and the card's reading the samples again.
 */
function holdTheReadAfterAChange() {
  const answer = globalThis.fetch;
  let changed = false;
  let asked = false;
  let release: () => void = () => undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal("fetch", async (input: Request) => {
    if (input.method === "POST") changed = true;
    else if (changed && new URL(input.url).pathname === SAMPLES) {
      asked = true;
      await held;
    }
    return answer(input);
  });
  return { release: () => { release(); }, asked: () => asked };
}

/** Every answer carries the server's clock, as the gateway's `Date` header does. */
function serverClockAt(at: string) {
  const answer = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: Request) => {
    const response = await answer(input);
    const headers = new Headers(response.headers);
    // An HTTP Date header for the client's clock, not a time printed for a person.
    // eslint-disable-next-line no-restricted-syntax
    headers.set("date", new Date(at).toUTCString());
    return new Response(response.body, { status: response.status, headers });
  });
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  forgetServerTime();
  // A toast outlives its test in the store, where the next test's page would show it.
  clearToasts();
});

describe("the getting started page", () => {
  it("starts with a safe example, from core's own reads alone (#496)", async () => {
    const seen = answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Try a safe example" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Setup steps" })).toBeInTheDocument();
    expect(screen.queryByText("Advanced: fixture inventory and developer recipes")).toBeNull();
    // Core's own two reads, the samples and the Space's setup (#678), and no edition's.
    expect([...new Set(seen.map((request) => request.path))].sort()).toEqual([SAMPLES, SETUP].sort());
  });

  it("puts the edition's part after the steps (#496)", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT } });
    renderPage(withEdition(<WelcomePage />, { Welcome: () => <p>Edition end</p> }));
    const end = await screen.findByText("Edition end");
    const steps = screen.getByRole("navigation", { name: "Setup steps" });
    expect(steps.compareDocumentPosition(end) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it.each([
    ["workstation", "ALLOW", "Allowed by example policy"],
    ["domain_controller", "DENY", "Denied by example policy"],
    ["production", "REQUIRE_APPROVAL", "Approval required"],
  ])("evaluates %s through the authenticated safe endpoint without claiming execution", async (scenario, decision, label) => {
    const seen = answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      "POST /api/console/v1/welcome/example": { body: { scenario, target: "Synthetic", decision, reason: "Example reason", facts: { Environment: "development" }, executed: false, scope: "Synthetic only" } },
    });
    renderPage(<WelcomePage />);
    await userEvent.selectOptions(await screen.findByLabelText("Example target"), scenario);
    await userEvent.click(screen.getByRole("button", { name: "Run safe example" }));
    expect(await screen.findByText(label)).toBeInTheDocument();
    expect(screen.getByText("Execution: none.")).toBeInTheDocument();
    const request = seen.find((item) => item.method === "POST");
    expect(request?.body).toEqual({ scenario });
    expect(request?.headers.get("X-CSRF-Token")).toBe("token-under-test");
    await userEvent.selectOptions(screen.getByLabelText("Example target"), scenario === "workstation" ? "production" : "workstation");
    expect(screen.queryByText(label)).toBeNull();
  });

  it("keeps server failures visible and does not manufacture a result", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      "POST /api/console/v1/welcome/example": { status: 503, body: { code: "UNAVAILABLE", detail: "Example unavailable" } },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Run safe example" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/try again|unavailable|could not/i);
    expect(screen.queryByText("Execution: none.")).toBeNull();
  });

  it("names each registered agent one way, with the handle beside a label (#678)", async () => {
    const agent = (row_id: string, name: string | null, number: number) => ({ row_id, name, number, live: 0, last_request: null });
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      "GET /api/console/v1/agents": {
        body: {
          agents: [agent("a1111111-0000-4000-8000-000000000001", null, 1), agent("a2222222-0000-4000-8000-000000000002", "triage-bot", 2)],
          next: null,
          line: { principals: 2 },
        },
      },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Next: Connect an agent" }));
    expect(await screen.findByRole("link", { name: "Agent 1" })).toHaveAttribute("href", "/agents/a1111111-0000-4000-8000-000000000001?section=connection");
    const labelled = screen.getByRole("link", { name: "triage-bot" });
    expect(labelled.parentElement).toHaveTextContent("triage-bot Agent 2");
    expect(screen.queryByText(/a1111111/)).toBeNull();
  });

  it("offers named agent setup and ordinary account-based reviewer setup", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      "GET /api/console/v1/agents": { body: { agents: [], next: null, line: { principals: 0 } } },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Next: Connect an agent" }));
    expect(await screen.findByText(/No active agent is configured/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Add agent" }));
    await userEvent.selectOptions(await screen.findByRole("combobox", { name: "Agent host" }), "mcp");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("textbox", { name: /Agent name/ })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: /4.*Set your controls/ }));
    expect(screen.getByRole("link", { name: "Set up reviewers" })).toHaveAttribute("href", "/people");
    expect(screen.getByText(/Administrators also need explicit review permissions/)).toBeInTheDocument();
  });
});

describe("sample targets", () => {
  it("offers them to an empty workspace, says what they add, and adds them with the session's token", async () => {
    let added = false;
    const seen = answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: added ? PRESENT : { ...ABSENT, offered: true } }),
      [`POST ${SAMPLES}`]: () => {
        added = true;
        return { body: PRESENT };
      },
    });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Sample targets" })).toBeInTheDocument();
    expect(screen.getByText("A domain controller the starter policy never lets anyone isolate.")).toBeInTheDocument();
    // Nothing to configure the command-line demo with until the samples exist.
    expect(screen.queryByRole("link", { name: "Download demo configuration" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Add sample targets" }));
    const table = await screen.findByRole("table", { name: /what the starter policy does/ });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    for (const [index, hostname, word] of [[0, "dc-01.sample.invalid", "Denied"], [1, "ws-dev-01.sample.invalid", "Allowed"], [2, "ws-prod-01.sample.invalid", "Needs approval"]] as const) {
      expect(rows[index]).toHaveTextContent(hostname);
      expect(rows[index]).toHaveTextContent("Sample");
      expect(rows[index]).toHaveTextContent(word);
    }
    const request = seen.find((item) => item.method === "POST");
    expect(request?.path).toBe(SAMPLES);
    expect(request?.body).toEqual({});
    expect(request?.headers.get("X-CSRF-Token")).toBe("token-under-test");
    expect(await screen.findByText("Sample targets added. The starter policy is active.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove sample targets" })).toBeEnabled();
  });

  it("is absent where the samples are not offered, as in a claimed sandbox", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Try a safe example" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sample targets" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Add sample targets" })).toBeNull();
  });

  it("offers the command-line demo's configuration for the samples, after the governed path", async () => {
    // The tab renders one session's workspace, as SessionProvider holds it from the session read.
    resetWorkspace();
    holdWorkspace("gen-7");
    try {
      answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, stale_at: FRESH_UNTIL } } });
      renderPage(<WelcomePage />);
      const link = await screen.findByRole("link", { name: "Download demo configuration" });
      // A download link carries no workspace header, so it names the tab's session generation,
      // as the report's CSV does: an account session's download without it is refused.
      const href = new URL(link.getAttribute("href") ?? "", "http://console.test");
      expect(href.pathname).toBe("/api/console/v1/samples/demo-configuration");
      expect([...href.searchParams.keys()]).toEqual(["generation"]);
      expect(href.searchParams.get("generation")).toBe("gen-7");
      expect(link).toHaveAttribute("download", "sandbox.json");
      const card = link.closest("section");
      expect(within(card ?? document.body).getByRole("heading", { name: "Sample targets" })).toBeInTheDocument();
      expect(within(card ?? document.body).getByText("execbound-demo")).toBeInTheDocument();
      // After the governed path: below the targets, their facts and what refreshing them does.
      const refresh = screen.getByRole("button", { name: "Refresh sample facts" });
      expect(refresh.compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(screen.getByRole("table", { name: /what the starter policy does/ }).compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(link.parentElement).toHaveTextContent(/boundary and approval beats on these targets from your own machine with an agent's API key/);
      expect(link.parentElement).toHaveTextContent(/an isolation of one that executes, by a run or by your own agent, changes it/);
      expect(link.parentElement).toHaveTextContent(/refresh the sample facts and download the configuration again before the next/);
      // A deployment that names no source still says where the client's guide is.
      expect(link.parentElement).toHaveTextContent(/as the Python client's guide \(clients\/python\/README\.md in the source repository\) describes/);
      expect(within(link.parentElement ?? document.body).queryByRole("link", { name: "the source repository" })).toBeNull();
    } finally {
      resetWorkspace();
    }
  });

  it("links the client's guide to the source this deployment names", async () => {
    const source = "https://code.example/execbound";
    answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, stale_at: FRESH_UNTIL } } });
    renderPage(<WelcomePage />, { ...PLACEHOLDER, service: { ...NO_SERVICE, source_url: source } });
    const download = await screen.findByRole("link", { name: "Download demo configuration" });
    const repository = within(download.parentElement ?? document.body).getByRole("link", { name: "the source repository" });
    expect(repository).toHaveAttribute("href", source);
    expect(download.parentElement).toHaveTextContent(/as the Python client's guide \(clients\/python\/README\.md in the source repository\) describes/);
  });

  it("offers no demo configuration while the server says the demo cannot run on the samples", async () => {
    // This deployment no longer serves them, the starter's isolation mapping is not live, a
    // target has no open incident or the emergency stop is active: the server answers the
    // download 404, so there is no link. The facts are current by the card's own clock, so the
    // server's verdict is all that keeps the link away, and none of these is one a refresh mends.
    answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, stale_at: FRESH_UNTIL, demo_available: false } } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("table", { name: /what the starter policy does/ })).toBeInTheDocument();
    expect(screen.queryByText("Stale")).toBeNull();
    expect(screen.queryByRole("link", { name: "Download demo configuration" })).toBeNull();
    expect(screen.queryByText("execbound-demo")).toBeNull();
    expect(screen.queryByText(/offered while the sample facts are current/)).toBeNull();
  });

  /** The card's words in the download's place, when a refresh is what the demo waits for. */
  function refreshWords(): HTMLElement {
    const words = screen.getByText(/offered while the sample facts are current/);
    expect(words).toHaveTextContent(/execbound-demo/);
    expect(words).toHaveTextContent(/Its configuration is offered while the sample facts are current and record the targets as they are, which they stop doing when the facts go stale or a request, your own agent's or a run's, isolates a target; refresh the sample facts to download it\./);
    return words;
  }

  it.each([
    // Guided setup's own requests isolate the sample workstation and, approved, the production
    // one, past the version the facts record.
    ["a request has changed a sample target", FRESH_UNTIL],
    // The starter keeps the facts an hour and nothing records them again but a refresh.
    ["the sample facts have gone stale", PRESENT.stale_at],
  ])("says a refresh is what the demo waits for once %s", async (_case, staleAt) => {
    // The server answers the download 404 until a refresh, and says so, so the card says to
    // refresh rather than offer a file that fails.
    answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, stale_at: staleAt, demo_available: false, demo_needs_refresh: true } } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("table", { name: /what the starter policy does/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Download demo configuration" })).toBeNull();
    const words = refreshWords();
    const refresh = screen.getByRole("button", { name: "Refresh sample facts" });
    expect(refresh.compareDocumentPosition(words) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("offers no demo configuration on facts that have gone stale since the server read them", async () => {
    // The server read the samples while their facts were current; by the server's clock they
    // are stale now, and the route answers the download 404 from that instant, as admission
    // refuses every request on them before a decision.
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    renderPage(<WelcomePage />);
    expect(await screen.findByText("Stale")).toHaveClass("badge-stale");
    expect(screen.queryByRole("link", { name: "Download demo configuration" })).toBeNull();
    refreshWords();
  });

  it("takes the demo configuration back when the facts go stale with the page left open", async () => {
    vi.useFakeTimers({ now: Date.parse("2026-09-24T11:00:00+00:00") - 10_000 });
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    renderPage(<WelcomePage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByRole("link", { name: "Download demo configuration" })).toBeInTheDocument();
    expect(screen.queryByText(/offered while the sample facts are current/)).toBeNull();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(screen.getByText("Stale")).toHaveClass("badge-stale");
    expect(screen.queryByRole("link", { name: "Download demo configuration" })).toBeNull();
    refreshWords();
  });

  it("holds refreshing and removal back while a sample request waits", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, state: "present" } } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("button", { name: "Remove sample targets" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeDisabled();
    expect(screen.getByText(/Settle it in Approvals or Activity before refreshing or removing the samples/)).toBeInTheDocument();
  });

  it("refreshes the sample facts with the session's token, says what that re-creates, and shows the new incidents", async () => {
    let refreshed = false;
    const seen = answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: REFRESHED };
      },
    });
    renderPage(<WelcomePage />);
    const refreshes = await screen.findByText(/^Refreshing re-creates the sample targets/);
    // One disclosure away beside the button it explains (UX17, #678).
    expect(refreshes).not.toBeVisible();
    await userEvent.click(screen.getByText("What a refresh changes"));
    expect(refreshes).toBeVisible();
    expect(refreshes).toHaveTextContent(
      "Refreshing re-creates the sample targets with new incidents, so your agent needs the new request from Verify protection, with a new reference: one already recorded on the same target brings back that request's answer. Review of the samples returns to you alone, as when they were added, and the starter policy is activated again. Requests already made stay in Activity.",
    );
    await userEvent.click(screen.getByRole("button", { name: "Refresh sample facts" }));
    expect(await screen.findByText(`Sample facts refreshed. Each target has a new incident, and the facts stay current until ${dateTime(FRESH_UNTIL)}.`)).toBeInTheDocument();
    const request = seen.find((item) => item.method === "POST");
    expect([request?.path, request?.body]).toEqual([`${SAMPLES}/refresh`, {}]);
    expect(request?.headers.get("X-CSRF-Token")).toBe("token-under-test");
    expect(await screen.findByText("33333333-0000-4000-8000-000000000002")).toBeInTheDocument();
    expect(screen.queryByText("Stale")).toBeNull();
  });

  it("holds both buttons while a refresh is on its way, so a second click sends nothing", async () => {
    let refreshed = false;
    const seen = answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: REFRESHED };
      },
    });
    // The refresh is held until released, so the test can look at the card while it is in flight.
    const answer = globalThis.fetch;
    let release: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    vi.stubGlobal("fetch", async (input: Request) => {
      if (input.method === "POST") await held;
      return answer(input);
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    const pending = await screen.findByRole("button", { name: "Refreshing sample facts…" });
    expect(pending).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove sample targets" })).toBeDisabled();
    await userEvent.click(pending);
    release();
    expect(await screen.findByText(/^Sample facts refreshed/)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
    expect(seen.filter((item) => item.method === "POST")).toHaveLength(1);
  });

  it("shows the samples as the server reads them after a refresh, never the refresh's own answer, and reads the connection again", async () => {
    let refreshed = false;
    // An answer that is already out of date by the time it arrives, as when another
    // administrator refreshed straight after: its incidents no longer exist.
    const outdated: SampleStatusView = { ...REFRESHED, hosts: REFRESHED.hosts.map((host) => ({ ...host, incident_id: (host.incident_id ?? "").replace("33333333", "44444444") })) };
    const seen = answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: outdated };
      },
      [`GET ${CONNECTION}`]: { body: CONNECTED },
    });
    const read = holdTheReadAfterAChange();
    renderPage(<><WelcomePage /><ConnectionRead /></>);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    // The refresh has answered and the card has asked for the samples again: until they come, it
    // shows what it had, never the answer's incidents.
    await waitFor(() => { expect(read.asked()).toBe(true); });
    expect(screen.getByText("22222222-0000-4000-8000-000000000002")).toBeInTheDocument();
    expect(screen.queryByText("44444444-0000-4000-8000-000000000002")).toBeNull();
    read.release();
    expect(await screen.findByText("33333333-0000-4000-8000-000000000002")).toBeInTheDocument();
    expect(screen.queryByText("44444444-0000-4000-8000-000000000002")).toBeNull();
    await waitFor(() => {
      const after = seen.slice(seen.findIndex((item) => item.method === "POST") + 1).map((item) => `${item.method} ${item.path}`);
      expect(after).toEqual(expect.arrayContaining([`GET ${SAMPLES}`, `GET ${CONNECTION}`]));
    });
  });

  it("marks facts past their stale time as Stale, in the words the agent is answered in", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    renderPage(<WelcomePage />);
    expect(await screen.findByText("Stale")).toHaveClass("badge-stale");
    expect(screen.getByText(/went stale at/)).toHaveTextContent(
      `Facts recorded ${dateTime("2026-09-24T10:00:00+00:00")} went stale at ${dateTime("2026-09-24T11:00:00+00:00")}: a request on them is refused before any decision, and your agent is told only that execution is unavailable. Refresh the sample facts to record them again.`,
    );
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
  });

  it("shows no Stale badge while the facts are current, and says when they go stale", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: { ...PRESENT, stale_at: FRESH_UNTIL } } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
    expect(screen.queryByText("Stale")).toBeNull();
    expect(screen.getByText(/refused before any decision/)).toHaveTextContent(
      `From ${dateTime(FRESH_UNTIL)} a request on them is refused before any decision, and your agent is told only that execution is unavailable; refresh the sample facts to record them again.`,
    );
  });

  it("marks the facts Stale when they go stale, with the page left open and nothing new to read", async () => {
    // The card reads the samples once; nothing re-renders it when their facts go stale, so the
    // badge needs a clock of its own to appear.
    vi.useFakeTimers({ now: Date.parse("2026-09-24T11:00:00+00:00") - 10_000 });
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    renderPage(<WelcomePage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    // The samples have answered, so nothing but the clock is left to change the card.
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
    expect(screen.queryByText("Stale")).toBeNull();
    expect(screen.getByText(/refused before any decision/)).toHaveTextContent(`From ${dateTime("2026-09-24T11:00:00+00:00")} a request on them`);
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(screen.getByText("Stale")).toHaveClass("badge-stale");
    expect(screen.getByText(/went stale at/)).toHaveTextContent(`went stale at ${dateTime("2026-09-24T11:00:00+00:00")}: a request on them is refused before any decision`);
  });

  it("keeps the refresh on its way until the card has read the new samples", async () => {
    let refreshed = false;
    answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: REFRESHED };
      },
    });
    const read = holdTheReadAfterAChange();
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    await waitFor(() => { expect(read.asked()).toBe(true); });
    // The old incidents are still on the card, so nothing yet says there are new ones.
    expect(screen.getByRole("button", { name: "Refreshing sample facts…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove sample targets" })).toBeDisabled();
    expect(screen.queryByText(/^Sample facts refreshed/)).toBeNull();
    read.release();
    expect(await screen.findByText(/^Sample facts refreshed/)).toBeInTheDocument();
    expect(screen.getByText("33333333-0000-4000-8000-000000000002")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
  });

  it.each([
    [true, "There were no sample targets to refresh: they were removed since this page last read them. Add them again to try an example."],
    [false, "There were no sample targets to refresh: they were removed since this page last read them."],
  ])("says there was nothing to refresh where the samples were removed first (offered again: %s)", async (offered, words) => {
    let refreshed = false;
    const gone: SampleStatusView = { ...ABSENT, offered };
    answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? gone : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: gone };
      },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    expect(await screen.findByText(words)).toBeInTheDocument();
    expect(screen.queryByText(/^Sample facts refreshed/)).toBeNull();
    expect(screen.queryByRole("table", { name: /what the starter policy does/ })).toBeNull();
  });

  it.each([
    ["refresh", "refresh", async () => { await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" })); }],
    ["removal", "remove", async () => {
      await userEvent.click(await screen.findByRole("button", { name: "Remove sample targets" }));
      await userEvent.click(within(screen.getByRole("group", { name: "Confirm removal" })).getByRole("button", { name: "Remove" }));
    }],
  ])("reads the samples again after a refused %s, and holds both buttons while the request it met waits", async (_change, path, click) => {
    let refused = false;
    answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refused ? { ...PRESENT, state: "present" } : PRESENT }),
      [`POST ${SAMPLES}/${path}`]: () => {
        refused = true;
        return { status: 409, body: { code: "SAMPLES_BUSY", detail: "Refused." } };
      },
    });
    renderPage(<WelcomePage />);
    await click();
    expect(await screen.findByRole("alert")).toHaveTextContent("A sample request is waiting for approval or provider evidence");
    expect(await screen.findByText(/Settle it in Approvals or Activity before refreshing or removing the samples/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove sample targets" })).toBeDisabled();
  });

  it("clears a refused removal's words once a refresh goes through", async () => {
    let refreshed = false;
    answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: refreshed ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/remove`]: { status: 409, body: { code: "SAMPLES_NOT_OFFERED", detail: "Refused." } },
      [`POST ${SAMPLES}/refresh`]: () => {
        refreshed = true;
        return { body: REFRESHED };
      },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove sample targets" }));
    await userEvent.click(within(screen.getByRole("group", { name: "Confirm removal" })).getByRole("button", { name: "Remove" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    expect(await screen.findByText(/^Sample facts refreshed/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("never brings a refused refresh's words back after the samples are removed and added again", async () => {
    let state: "present" | "removed" | "added" = "present";
    answerWith({
      [`GET ${SAMPLES}`]: () => ({ body: state === "removed" ? { ...ABSENT, offered: true } : state === "added" ? REFRESHED : PRESENT }),
      [`POST ${SAMPLES}/refresh`]: { status: 409, body: { code: "SAMPLES_NOT_OFFERED", detail: "Refused." } },
      [`POST ${SAMPLES}/remove`]: () => {
        state = "removed";
        return { body: { ...ABSENT, offered: true } };
      },
      [`POST ${SAMPLES}`]: () => {
        state = "added";
        return { body: REFRESHED };
      },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove sample targets" }));
    await userEvent.click(within(screen.getByRole("group", { name: "Confirm removal" })).getByRole("button", { name: "Remove" }));
    await userEvent.click(await screen.findByRole("button", { name: "Add sample targets" }));
    expect(await screen.findByText("33333333-0000-4000-8000-000000000002")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("marks the facts Stale at the very moment they go stale, as the server refuses them", async () => {
    // The server refuses a plan whose facts are valid until now or earlier (`valid_until <= now`).
    vi.useFakeTimers({ now: Date.parse("2026-09-24T11:00:00+00:00") });
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    renderPage(<WelcomePage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByText("Stale")).toHaveClass("badge-stale");
  });

  it.each([
    ["the server's clock has passed it and the browser's has not", "2026-09-24T10:00:00+00:00", "2026-09-24T11:01:00+00:00", true],
    ["the browser's clock has passed it and the server's has not", "2026-09-24T12:00:00+00:00", "2026-09-24T10:00:00+00:00", false],
  ])("judges the stale time by the server's clock: %s", async (_case, browser, server, stale) => {
    vi.useFakeTimers({ now: Date.parse(browser) });
    answerWith({ [`GET ${SAMPLES}`]: { body: PRESENT } });
    serverClockAt(server);
    renderPage(<WelcomePage />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByRole("button", { name: "Refresh sample facts" })).toBeEnabled();
    expect(screen.queryByText("Stale") !== null).toBe(stale);
  });

  it.each([
    ["SAMPLES_BUSY", "A sample request is waiting for approval or provider evidence, so the sample facts were not refreshed and nothing changed. Settle it in Approvals or Activity; if its approval lapsed, ExecBound ends it at a scheduled recovery run, within about twenty minutes of the lapse, and the samples can be refreshed after that."],
    ["SAMPLES_NOT_OFFERED", "The sample facts were not refreshed, and nothing changed. Re-creating the samples would break a policy someone made that names them, or take the starter policy away from another space that uses it. A refresh is also refused once this workspace has a policy or connection of its own. A policy made from the starter policy, by copying it or from a template, stops a refresh until it is retired in Policies; if it is the active policy, activate the starter policy again first, then retire it."],
  ])("says in the refresh's own words why the server refused it (%s)", async (code, words) => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: PRESENT },
      [`POST ${SAMPLES}/refresh`]: { status: 409, body: { code, detail: "Refused." } },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Refresh sample facts" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(words);
    expect(screen.getByRole("table", { name: /what the starter policy does/ })).toBeInTheDocument();
  });

  it("removes them only after a confirmation, and says in words why the server refused", async () => {
    const seen = answerWith({
      [`GET ${SAMPLES}`]: { body: PRESENT },
      "POST /api/console/v1/samples/remove": { status: 409, body: { code: "SAMPLES_BUSY", detail: "Refused." } },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: "Remove sample targets" }));
    expect(seen.filter((item) => item.method === "POST")).toHaveLength(0);
    const group = screen.getByRole("group", { name: "Confirm removal" });
    await userEvent.click(within(group).getByRole("button", { name: "Remove" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A sample request is waiting for approval or provider evidence. Settle it before removing the samples.",
    );
    expect(seen.filter((item) => item.method === "POST").map((item) => [item.path, item.body])).toEqual([
      ["/api/console/v1/samples/remove", {}],
    ]);
    expect(screen.getByRole("table", { name: /what the starter policy does/ })).toBeInTheDocument();
  });

  it("shows the first sample request in Verify protection and suggests the two targets left", async () => {
    const first = { execution_id: "33333333-0000-4000-8000-000000000001", state: "EXECUTED", state_label: "Executed", provider_id: "sample-ws-dev-01", created_at: "2026-09-24T10:05:00+00:00" };
    answerWith({
      [`GET ${SAMPLES}`]: { body: { ...PRESENT, first_request: first } },
      "GET /api/console/v1/agents": { body: { agents: [], next: null, line: { principals: 0 } } },
    });
    renderPage(<WelcomePage />);
    await userEvent.click(await screen.findByRole("button", { name: /3.*Verify protection/ }));
    const link = await screen.findByRole("link", { name: "sample-ws-dev-01" });
    expect(link).toHaveAttribute("href", `/activity?open=${first.execution_id}`);
    expect(link.closest("p")).toHaveTextContent("First request: sample-ws-dev-01 Executed");
    expect(screen.getByText("dc-01.sample.invalid").closest("li")).toHaveTextContent("The starter policy denies a domain controller");
    const held = screen.getByText("ws-prod-01.sample.invalid").closest("li");
    if (held === null) throw new Error("no suggestion for the production workstation");
    expect(held).toHaveTextContent("22222222-0000-4000-8000-000000000002");
    expect(within(held).getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals");
  });
});

describe("progress from records (UX10, #678)", () => {
  const AGENTS = "/api/console/v1/agents";
  const NONE = { agents: [], next: null };
  const OFFERED: SampleStatusView = { ...ABSENT, offered: true };

  it("opens on the first undone step, ticks done steps and links their records", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView({ agent_key: "done", first_request: "done", policy: "done", reviewer: "done" }) },
      [`GET ${AGENTS}`]: { body: NONE },
    });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Choose your policy" })).toBeInTheDocument();
    const steps = screen.getByRole("navigation", { name: "Setup steps" });
    expect(within(steps).getByRole("button", { name: /Connect an agent, done/ })).toBeInTheDocument();
    expect(within(steps).getByRole("button", { name: /Verify protection, done/ })).toBeInTheDocument();
    expect(within(steps).getByRole("button", { name: /^\d?Set your controls$/ })).toBeInTheDocument();
    expect(within(steps).getByRole("button", { name: /Try an example$/ })).toBeInTheDocument();
    const policy = screen.getByText(/Policy active since/);
    expect(within(policy).getByRole("link", { name: "Open the policy" })).toHaveAttribute("href", `/policy/${POLICY}`);
    expect(policy.querySelector("time")).toHaveAttribute("dateTime", AT);
    await userEvent.click(within(steps).getByRole("button", { name: /Verify protection/ }));
    const first = await screen.findByText(/First request/);
    expect(within(first).getByRole("link", { name: "EB-12" })).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
  });

  it("names the first decision's record once one is decided", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView({ agent_key: "done", first_request: "done", policy: "done", reviewer: "done", first_decision: "done" }) },
    });
    renderPage(<WelcomePage />);
    const decided = await screen.findByText(/First approval decided/);
    expect(within(decided).getByRole("link", { name: "EB-14" })).toHaveAttribute("href", `/activity?open=${DECIDED}`);
  });

  it("calls onStep with the opening step once, as a replacement, and Next as a push", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView({ agent_key: "done" }) },
      [`GET ${AGENTS}`]: { body: NONE },
    });
    const onStep = vi.fn();
    renderPage(<WelcomePage onStep={onStep} />);
    expect(await screen.findByRole("heading", { name: "Verify protection" })).toBeInTheDocument();
    await waitFor(() => {
      expect(onStep).toHaveBeenCalledWith("verify", { replace: true });
    });
    expect(onStep).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Next: Set your controls" }));
    expect(onStep).toHaveBeenLastCalledWith("controls", undefined);
  });

  it("opens the step it is given without writing the address", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView() },
      [`GET ${AGENTS}`]: { body: NONE },
    });
    const onStep = vi.fn();
    renderPage(<WelcomePage step="verify" onStep={onStep} />);
    expect(await screen.findByRole("heading", { name: "Verify protection" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(onStep).toHaveBeenCalledTimes(1);
    expect(onStep).toHaveBeenCalledWith("connect", undefined);
  });

  it("shows only the loading line until both reads answer, then one step", async () => {
    const setup = heldReply();
    answerWith({
      [`GET ${SAMPLES}`]: { body: OFFERED },
      [`GET ${SETUP}`]: () => setup.reply,
      [`GET ${AGENTS}`]: { body: NONE },
    });
    renderPage(<WelcomePage />);
    expect(await screen.findByText("Loading setup…")).toBeInTheDocument();
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(screen.queryByRole("navigation", { name: "Setup steps" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Try a safe example" })).toBeNull();
    setup.send({ body: setupView({ agent_key: "done" }) });
    expect(await screen.findByRole("heading", { name: "Verify protection" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Try a safe example" })).toBeNull();
  });

  it("opens on Try an example with no tick where the setup read fails", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT } });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Try a safe example" })).toBeInTheDocument();
    expect(screen.queryByText(/, done/)).toBeNull();
  });

  it("says samples go to the default Space where another Space is selected", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: OFFERED },
      [`GET ${SETUP}`]: { body: setupView({}, { connected: false, samples_here: false }) },
      [`GET ${AGENTS}`]: { body: NONE },
    });
    renderPage(<WelcomePage />);
    expect(await screen.findByRole("heading", { name: "Connect an agent" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Try an example/ }));
    expect(await screen.findByText("Sample targets are added to the workspace's default Space, not the Space selected in the sidebar.")).toBeInTheDocument();
  });

  it("asks for a Space where the session looks at all of them", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT }, [`GET ${SETUP}`]: { body: CHOOSE_SPACE } });
    renderPage(<WelcomePage />);
    expect(await screen.findByText("Choose a Space in the sidebar to see what is left to set up in it.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Try a safe example" })).toBeInTheDocument();
  });
});

describe("what an empty Space needs, on Connect an agent (UX12, UX18, #678)", () => {
  const AGENTS = "/api/console/v1/agents";
  const NONE = { agents: [], next: null };
  const OFFERED: SampleStatusView = { ...ABSENT, offered: true };

  async function connect(setup: ReturnType<typeof setupView>, samples: SampleStatusView = ABSENT, edition: Parameters<typeof withEdition>[1] = {}) {
    answerWith({ [`GET ${SAMPLES}`]: { body: samples }, [`GET ${SETUP}`]: { body: setup }, [`GET ${AGENTS}`]: { body: NONE } });
    renderPage(withEdition(<WelcomePage step="connect" onStep={() => undefined} />, edition));
    return screen.findByRole("heading", { name: "Connect an agent" });
  }

  it("says requests are refused without a connection, and offers the example here", async () => {
    await connect(setupView({}, { connected: false }), OFFERED);
    expect(screen.getByText("Requests from agents are refused until this Space has a registered connection and an active policy.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Try an example" })).toHaveAttribute("href", "/welcome?step=example");
  });

  it("says samples go to the default Space, then gives the operator's steps, in another Space", async () => {
    await connect(setupView({}, { connected: false, samples_here: false }), OFFERED);
    expect(screen.queryByRole("link", { name: "Try an example" })).toBeNull();
    expect(screen.getByText(/added to the workspace's default Space, not this one/)).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Copy instructions for your operator" })).toBeInTheDocument();
  });

  it("gives the operator's steps where no samples are offered", async () => {
    await connect(setupView({}, { connected: false }), ABSENT);
    expect(screen.getByRole("region", { name: "Copy instructions for your operator" })).toBeInTheDocument();
  });

  it("asks for a policy once connected", async () => {
    await connect(setupView({}, { connected: true }), ABSENT);
    expect(screen.getByText("Requests from agents are refused until a policy is active in this Space.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Choose a policy" })).toHaveAttribute("href", "/policy");
  });

  it("offers watching first below the governed path, only while no request has arrived", async () => {
    await connect(setupView({ policy: "done" }), ABSENT);
    const line = screen.getByText(/Or start by watching what your Tines stories and Entra agents can already do/);
    expect(line).toHaveTextContent("it does not block anything");
    expect(within(line).getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
  });

  it("offers no watching first once a request has arrived", async () => {
    await connect(setupView({ policy: "done", agent_key: "done", first_request: "done" }), ABSENT);
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
  });

  it("offers no watching first in an edition that cannot finish monitoring setup", async () => {
    await connect(setupView({ policy: "done" }), ABSENT, { watchFirst: false });
    expect(screen.queryByText(/Or start by watching/)).toBeNull();
  });
});

describe("hiding the sidebar's setup progress (UX11, #678)", () => {
  const TENANT = "11111111-1111-4111-8111-111111111111";

  afterEach(() => {
    localStorage.clear();
  });

  it("toggles this browser's preference for this workspace, and its own words", async () => {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT }, [`GET ${SETUP}`]: { body: setupView() } });
    renderPage(<WelcomePage />, { ...PLACEHOLDER, role: "ADMIN", tenant: { id: TENANT, name: "Acme", detail: "" } });
    await userEvent.click(await screen.findByRole("button", { name: "Hide setup progress in the sidebar" }));
    expect(localStorage.getItem(`execbound.setup-card.hidden.${TENANT}`)).toBe("1");
    await userEvent.click(screen.getByRole("button", { name: "Show setup progress in the sidebar" }));
    expect(localStorage.getItem(`execbound.setup-card.hidden.${TENANT}`)).toBeNull();
    expect(screen.getByRole("button", { name: "Hide setup progress in the sidebar" })).toBeInTheDocument();
  });
});

describe("Set your controls (UX15, UX18, #678)", () => {
  async function controls(setup: ReturnType<typeof setupView>, edition: Parameters<typeof withEdition>[1] = {}, session = { ...PLACEHOLDER, role: "ADMIN" as const, mode: "ENFORCE" as const }) {
    answerWith({ [`GET ${SAMPLES}`]: { body: ABSENT }, [`GET ${SETUP}`]: { body: setup } });
    renderPage(withEdition(<WelcomePage step="controls" onStep={() => undefined} />, edition), session);
    return screen.findByRole("heading", { name: "Choose your policy" });
  }

  it("orders policy, review, the pilot and discovery, and says nobody can review yet", async () => {
    await controls(setupView({ policy: "done" }));
    const titles = screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent);
    expect(titles).toEqual(["Choose your policy", "Choose who can review", "Pilot in Observe only (optional)", "Discover other activity"]);
    expect(screen.getByText("Nobody in this Space can review the actions your policy holds yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Connect a monitoring source" })).toHaveAttribute("href", "/monitor?setup=tines");
  });

  it("drops the review sentence once someone can review", async () => {
    await controls(setupView({ policy: "done", reviewer: "done" }));
    expect(screen.queryByText("Nobody in this Space can review the actions your policy holds yet.")).toBeNull();
  });

  it("links no Monitoring and names the service operator in an edition that cannot finish its setup", async () => {
    await controls(setupView({ policy: "done" }), { watchFirst: false }, { ...PLACEHOLDER, role: "ADMIN", mode: "ENFORCE", service: { ...NO_SERVICE, support_email: "help@example.com" } });
    const discover = screen.getByRole("heading", { name: "Discover other activity" }).closest("section");
    if (discover === null) throw new Error("No Discover card");
    expect(discover).toHaveTextContent("Monitoring setup in the console comes later here. Ask your service operator to connect a source: help@example.com.");
    expect(discover.querySelector('a[href^="/monitor"]')).toBeNull();
    expect(within(discover).getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
  });
});

describe("Verify protection's records (UX13, #678)", () => {
  it("links each agent's newest request by its reference", async () => {
    const agent = {
      row_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", population: "governed", principal_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", agent_id: null,
      name: "Triage bot", number: 2, active: true, dormant: false, source: null, source_label: "", identity_class: null, class_label: "",
      enabled: null, gone_at: null, last_seen: null, sponsors: [], sponsor_state: null, live: 1, requests: 1,
      last_request: "2026-10-08T09:30:00Z", last_execution_id: EXECUTION, last_request_ref: "EB-12",
      consequential: 0, governed_paths: 0, lapsed: 0, findings: 0,
    };
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView() },
      "GET /api/console/v1/agents": { body: { agents: [agent], next: null } },
    });
    renderPage(<WelcomePage step="verify" onStep={() => undefined} />);
    expect(await screen.findByRole("link", { name: "EB-12" })).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
  });
});

describe("caveats one disclosure away (UX17, #678)", () => {
  it("keeps Verify protection's closing caveat behind its summary and the four checks in view", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView() },
      "GET /api/console/v1/agents": { body: { agents: [], next: null } },
    });
    renderPage(<WelcomePage step="verify" onStep={() => undefined} />);
    const caveat = await screen.findByText(/A successful connection or tool list alone does not verify the execution path\./);
    expect(caveat.closest("details")?.querySelector("summary")).toHaveTextContent("What a connection does not prove");
    expect(caveat).not.toBeVisible();
    expect(screen.getByText(/Monitoring alone does not prevent actions\./)).toBeVisible();
    await userEvent.click(screen.getByText("What a connection does not prove"));
    expect(caveat).toBeVisible();
  });

  it("keeps Connect an agent's last line about bypass in view", async () => {
    answerWith({
      [`GET ${SAMPLES}`]: { body: ABSENT },
      [`GET ${SETUP}`]: { body: setupView() },
      "GET /api/console/v1/agents": { body: { agents: [], next: null } },
    });
    renderPage(<WelcomePage step="connect" onStep={() => undefined} />);
    expect(await screen.findByText(/Remove direct access to protected provider credentials from the agent to prevent bypass\./)).toBeVisible();
  });
});
