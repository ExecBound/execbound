// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MonitorSetupVerification, MonitorSnapshot } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { MonitorPage } from "./MonitorPage";
import { MonitorSetup } from "./MonitorSetup";
import { setupInstructions, type MonitorProvider } from "./setup";

const CONNECTION = "cccccccc-0000-4000-8000-000000000001";
const SPACE = "aaaaaaaa-0000-4000-8000-000000000002";
const session: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", spaces: 2, space: { id: SPACE, name: "Customer A", archived: false } };
const empty: MonitorSnapshot = { connections: [], sources: [], stories: [], credentials: [], observations: [], findings: [], deliveries: [], destinations: [], profile: null, open_findings: 0, synthetic_directory: { present: false, addable: true } };

function evidence(changes: Partial<MonitorSetupVerification> = {}): MonitorSetupVerification {
  return {
    connection_id: CONNECTION, label: "Collected <b>metadata</b>", provider: "tines",
    state: "awaiting_sync", last_run_at: null, last_sync_at: null, last_outcome: null,
    last_error_code: null, health_state: "NEVER_COLLECTED", capabilities: {},
    recent_observations: 0, latest_observation_at: null, checked_at: "2026-09-22T10:00:00Z", ...changes,
  };
}

afterEach(() => { vi.unstubAllGlobals(); clearToasts(); });

describe("guided monitoring setup", () => {
  it("offers an actionable connection flow on an empty Monitoring page", async () => {
    answerWith({ "GET /api/console/v1/monitor": { body: empty } });
    renderPage(<MonitorPage />, session);
    await userEvent.click(await screen.findByRole("button", { name: "Connect a source" }));
    const dialog = await screen.findByRole("dialog", { name: "Connect a source" });
    expect(within(dialog).getByRole("combobox", { name: "Provider" })).toHaveValue("tines");
    expect(within(dialog).getByRole("option", { name: "Other providers — unavailable" })).toBeDisabled();
    expect(within(dialog).getByText(/does not prevent actions/)).toBeInTheDocument();
    expect(within(dialog).getByText(/with access to this deployment's database/)).toBeInTheDocument();
  });

  it.each<MonitorProvider>(["tines", "entra_agent_id"])("generates the supported %s operator commands for the current Space", async (provider) => {
    answerWith({});
    renderPage(<MonitorSetup onClose={() => undefined} />, session);
    await screen.findByRole("dialog");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Provider" }), provider);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    if (provider === "entra_agent_id") {
      expect(screen.getByText(/AgentIdentity.Read.All/)).toHaveTextContent("Application.Read.All, AuditLog.Read.All and Directory.Read.All");
      expect(screen.getByText(/Keep it separate from any app that executes/)).toBeInTheDocument();
    } else {
      await userEvent.type(screen.getByRole("textbox", { name: "Tines team ID (optional)" }), "7");
      expect(screen.getByText(/read access to stories, actions and credential metadata/)).toBeInTheDocument();
    }
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    const command = screen.getByLabelText("Registration command");
    expect(command).toHaveTextContent(`--kind ${provider}`);
    expect(command).toHaveTextContent(`--space ${SPACE}`);
    expect(command).toHaveTextContent("--credential-file local-data/admin-token.txt");
    const environment = screen.getByLabelText("Environment template");
    expect(environment).toHaveTextContent(provider === "tines" ? "TINES_API_KEY=REPLACE_WITH_READ_ONLY_API_KEY" : "ENTRA_CLIENT_SECRET=REPLACE_WITH_COLLECTION_APP_SECRET");
    await userEvent.type(screen.getByRole("textbox", { name: "Connection ID returned by registration" }), CONNECTION);
    expect(screen.getByLabelText("Collection command")).toHaveTextContent(`--connection ${CONNECTION}`);
    expect(screen.getByLabelText("Collection command")).toHaveTextContent(provider === "tines" ? "collect-tines" : "collect-entra");
    expect(screen.getByText(/No schedule is created here/)).toBeInTheDocument();
    expect(screen.queryByText("Reporting — first sync verified")).toBeNull();
  });

  it("does not generate a registration into an ambiguous Space", async () => {
    answerWith({});
    renderPage(<MonitorSetup onClose={() => undefined} />, { ...session, space: null });
    await userEvent.click(await screen.findByRole("button", { name: "Continue" }));
    expect(screen.getByRole("alert")).toHaveTextContent("choose a Space");
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("names the space switcher, where a Space is chosen, under All spaces (#678)", async () => {
    answerWith({});
    renderPage(<MonitorSetup onClose={() => undefined} />, { ...session, space: null });
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/^Choose a Space in the space switcher first/)).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("workspace switcher");
  });

  it("refuses registration guidance for an archived Space", async () => {
    answerWith({});
    renderPage(<MonitorSetup onClose={() => undefined} />, { ...session, space: { id: SPACE, name: "Archived customer", archived: true } });
    await userEvent.click(await screen.findByRole("button", { name: "Continue" }));
    expect(screen.getByRole("alert")).toHaveTextContent("This Space is archived");
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("keeps registration awaiting first sync and only accepts a reporting result from the API", async () => {
    let report = evidence();
    const seen = answerWith({ "POST /api/console/v1/monitor/setup/verify": () => ({ body: report }) });
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText("Registered — awaiting first sync")).toBeInTheDocument();
    expect(screen.getByText("Collected <b>metadata</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    const post = seen.find((request) => request.method === "POST");
    expect(post?.body).toEqual({ provider: "tines", connection_id: CONNECTION });
    expect(post?.headers.get("x-csrf-token")).toBe("token-under-test");
    report = evidence({ state: "reporting", last_run_at: "2026-09-22T09:58:00Z", last_sync_at: "2026-09-22T09:58:00Z", last_outcome: "COMPLETE", capabilities: { stories: { state: "available", at: null }, audit: { state: "unsupported", at: null } } });
    await userEvent.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByText("Reporting — first sync verified")).toBeInTheDocument();
    expect(screen.getByText(/does not prove complete coverage/)).toBeInTheDocument();
    expect(screen.getByText("audit: unsupported")).toBeInTheDocument();
    expect(screen.getByText(/No event in this view/)).toBeInTheDocument();
    // What to do after it reports (#678): govern a story through an agent of its own.
    expect(screen.getByRole("link", { name: "Govern a story: add an agent for it and choose Tines story as its host" })).toHaveAttribute("href", "/agents");
  });

  it("offers Entra's next step once it reports, and neither while awaiting a sync (UX18, #678)", async () => {
    let report = evidence({ provider: "entra_agent_id" });
    answerWith({ "POST /api/console/v1/monitor/setup/verify": () => ({ body: report }) });
    renderPage(<MonitorSetup onClose={() => undefined} provider="entra_agent_id" connectionId={CONNECTION} />, session);
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText("Registered — awaiting first sync")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Review agents with consequential reach/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Govern a story/ })).toBeNull();
    report = evidence({ provider: "entra_agent_id", state: "reporting", last_run_at: "2026-09-22T09:58:00Z", last_outcome: "COMPLETE" });
    await userEvent.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByRole("link", { name: "Review agents with consequential reach that nothing governs" })).toHaveAttribute("href", "/agents?ungoverned=yes");
  });

  it("shows failures without an earlier success and resets verification when the identifier changes", async () => {
    let refused = false;
    answerWith({ "POST /api/console/v1/monitor/setup/verify": () => refused ? { status: 403, body: { code: "FORBIDDEN" } } : { body: evidence({ state: "reporting" }) } });
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText("Reporting — first sync verified")).toBeInTheDocument();
    refused = true;
    await userEvent.click(screen.getByRole("button", { name: "Check connection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Confirm the connection ID, provider and current Space");
    expect(screen.queryByText("Reporting — first sync verified")).toBeNull();
    await userEvent.clear(screen.getByRole("textbox", { name: "Connection ID" }));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Check connection" })).toBeDisabled();
  });

  it.each(["attention", "inactive"] as const)("renders the server's %s state with its next action", async (state) => {
    answerWith({ "POST /api/console/v1/monitor/setup/verify": { body: evidence({ state, last_error_code: "AUTH_LOST" }) } });
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText(state === "attention" ? "Collection needs attention" : "Connection is inactive")).toBeInTheDocument();
    expect(screen.getByText("AUTH_LOST")).toBeInTheDocument();
    expect(screen.queryByText("Reporting — first sync verified")).toBeNull();
  });

  it("keeps shell metacharacters out of generated commands", () => {
    for (const label of ['a"; whoami', "a$(whoami)", "a`whoami`", "a\nwhoami", "a'whoami"]) {
      expect(setupInstructions({ provider: "tines", label, team: "", space: SPACE })).toBeNull();
    }
    expect(setupInstructions({ provider: "tines", label: "Safe label", team: "7;whoami", space: SPACE })).toBeNull();
    expect(setupInstructions({ provider: "tines", label: "Safe label", team: "", space: "foreign;whoami" })).toBeNull();
  });
});

describe("the Verify step listens for the first sync (MQ8, #678)", () => {
  function verifyCalls(seen: { method: string; path: string }[]): number {
    return seen.filter((request) => request.method === "POST" && request.path === "/api/console/v1/monitor/setup/verify").length;
  }

  async function advance(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  }

  function setup(answers: () => { status?: number; body: unknown }) {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const seen = answerWith({ "POST /api/console/v1/monitor/setup/verify": answers });
    const user = userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });
    return { seen, user };
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  it("checks again every 10 seconds while awaiting sync, and stops on reporting", async () => {
    let report = evidence();
    const { seen, user } = setup(() => ({ body: report }));
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await user.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText(/Listening for the first completed collection run/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stop listening" })).toBeInTheDocument();
    expect(verifyCalls(seen)).toBe(1);
    await advance(10_000);
    expect(verifyCalls(seen)).toBe(2);
    report = evidence({ state: "reporting" });
    await advance(10_000);
    expect(verifyCalls(seen)).toBe(3);
    expect(await screen.findByText("Reporting — first sync verified")).toBeInTheDocument();
    await advance(30_000);
    expect(verifyCalls(seen)).toBe(3);
    expect(screen.queryByText(/Listening for the first/)).toBeNull();
  });

  it("stops when asked", async () => {
    const { seen, user } = setup(() => ({ body: evidence() }));
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await user.click(await screen.findByRole("button", { name: "Check connection" }));
    await user.click(await screen.findByRole("button", { name: "Stop listening" }));
    await advance(30_000);
    expect(verifyCalls(seen)).toBe(1);
  });

  it("stops on an error with the existing copy", async () => {
    let refused = false;
    const { seen, user } = setup(() => (refused ? { status: 403, body: { code: "FORBIDDEN" } } : { body: evidence() }));
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await user.click(await screen.findByRole("button", { name: "Check connection" }));
    await screen.findByText(/Listening for the first/);
    refused = true;
    await advance(10_000);
    expect(await screen.findByRole("alert")).toHaveTextContent("Confirm the connection ID, provider and current Space");
    await advance(30_000);
    expect(verifyCalls(seen)).toBe(2);
  });

  it("stops after ten minutes and says so", async () => {
    const { seen, user } = setup(() => ({ body: evidence() }));
    renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await user.click(await screen.findByRole("button", { name: "Check connection" }));
    await screen.findByText(/Listening for the first/);
    for (let index = 0; index < 62; index += 1) await advance(10_000);
    expect(await screen.findByText("Stopped listening after 10 minutes. Check again once the collector has run.")).toBeInTheDocument();
    const calls = verifyCalls(seen);
    expect(calls).toBeLessThanOrEqual(61);
    await advance(60_000);
    expect(verifyCalls(seen)).toBe(calls);
  });

  it("makes no call once the dialog is closed", async () => {
    const { seen, user } = setup(() => ({ body: evidence() }));
    const view = renderPage(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, session);
    await user.click(await screen.findByRole("button", { name: "Check connection" }));
    await screen.findByText(/Listening for the first/);
    view.unmount();
    await advance(60_000);
    expect(verifyCalls(seen)).toBe(1);
  });
});

describe("where the edition offers no operator commands (MC18, #678)", () => {
  const HOST_STEPS = /DATABASE_URL|local-data|create-connection|collect-tines|collect-entra|trusted host|Customer-operated collector/;
  const served = (service: Partial<typeof NO_SERVICE>): SessionSummary => ({ ...session, service: { ...NO_SERVICE, ...service } });

  async function opened(commands: boolean, who: SessionSummary) {
    answerWith({});
    renderPage(withEdition(<MonitorSetup onClose={() => undefined} />, { operatorCommands: commands }), who);
    return screen.findByRole("dialog", { name: "Connect a source" });
  }

  it("keeps the operator steps unchanged where the edition offers operator commands", async () => {
    const dialog = await opened(true, served({ operator: "Example Operator", support_email: "help@example.com" }));
    expect(within(dialog).getByText("Step 1 of 4 · Choose a provider")).toBeInTheDocument();
    expect(within(dialog).getByRole("heading", { name: "Customer-operated collector" })).toBeInTheDocument();
    expect(within(dialog).queryByText(/connects this provider/)).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(within(dialog).getByLabelText("Registration command")).toHaveTextContent("--credential-file local-data/admin-token.txt");
  });

  it("names the configured operator and support address, and no host step", async () => {
    const dialog = await opened(false, served({ operator: "Example Operator", support_email: "help@example.com" }));
    const copy = within(dialog).getByText(/connects this provider/);
    expect(copy).toHaveTextContent(
      "Example Operator connects this provider for this workspace for now. Email help@example.com with the connection name and the Space it belongs in.",
    );
    expect(within(dialog).getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
    expect(within(dialog).getByText("Never send an API key, client secret or token by email.")).toBeInTheDocument();
    expect(dialog.textContent).not.toMatch(HOST_STEPS);
    // The guide goes from the provider straight to verifying a connection the operator made.
    expect(within(dialog).getByText("Step 1 of 2 · Choose a provider")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Verify connection" }));
    expect(within(dialog).getByText("Step 2 of 2 · Verify evidence")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Check connection" })).toBeDisabled();
    expect(dialog.textContent).not.toMatch(HOST_STEPS);
    await userEvent.click(within(dialog).getByRole("button", { name: "Back" }));
    expect(within(dialog).getByText("Step 1 of 2 · Choose a provider")).toBeInTheDocument();
  });

  it("says your service operator where the deployment names none", async () => {
    const dialog = await opened(false, served({ support_email: "help@example.com" }));
    expect(within(dialog).getByText(/connects this provider/)).toHaveTextContent(
      /^Your service operator connects this provider for this workspace for now\. Email help@example\.com/,
    );
  });

  it("ends the first sentence after for now and links nothing where no address is configured", async () => {
    const dialog = await opened(false, served({ operator: "Example Operator" }));
    expect(within(dialog).getByText(/connects this provider/)).toHaveTextContent(
      /^Example Operator connects this provider for this workspace for now\.$/,
    );
    expect(within(dialog).queryByRole("link")).toBeNull();
    expect(dialog.textContent).not.toMatch(/Email/);
  });

  it("verifies a registered connection without asking anyone to run a command", async () => {
    answerWith({ "POST /api/console/v1/monitor/setup/verify": { body: evidence() } });
    renderPage(withEdition(<MonitorSetup onClose={() => undefined} connectionId={CONNECTION} />, { operatorCommands: false }), served({ operator: "Example Operator" }));
    const dialog = await screen.findByRole("dialog", { name: "Connect a source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Check connection" }));
    expect(await within(dialog).findByText("Registered — awaiting first sync")).toBeInTheDocument();
    expect(within(dialog).getByText(/Check again once the first collection has run/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Stop listening" }));
    expect(dialog.textContent).not.toMatch(HOST_STEPS);
  });
});
