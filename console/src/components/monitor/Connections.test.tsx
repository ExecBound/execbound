// SPDX-License-Identifier: AGPL-3.0-only
// The Connections view where console connect is not configured (MC18, #678): with operator
// commands the empty state asks the reader to register a connection; without them it names who
// connects a provider and how to ask, with the deployment's own operator and support address.

import { act, cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MonitorSnapshot } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { connection, snapshot } from "../../test/monitor-data";
import { renderMonitor } from "../../test/monitor";
import { answerWith, renderPage, settle } from "../../test/page";
import { minted, options, SOURCE, source } from "../../test/source-data";
import { Connections } from "./Connections";

const empty: MonitorSnapshot = { connections: [], sources: [], stories: [], credentials: [], observations: [], findings: [], deliveries: [], destinations: [], profile: null, open_findings: 0, synthetic_directory: { present: false, addable: true } };
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };
const served = (service: Partial<typeof NO_SERVICE>): SessionSummary => ({ ...ADMIN, service: { ...NO_SERVICE, ...service } });

async function show(operatorCommands: boolean, session: SessionSummary) {
  answerWith({});
  renderPage(withEdition(<Connections data={empty} />, { operatorCommands }), session);
  const status = (await screen.findByText("No collection connection registered")).closest<HTMLElement>(".empty");
  if (status === null) throw new Error("no empty state");
  return status;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("the Connections empty state (MC18)", () => {
  it("asks the reader to register a connection where the edition offers operator commands", async () => {
    const empty = await show(true, served({ operator: "Example Operator", support_email: "help@example.com" }));
    expect(empty).toHaveTextContent("Register a read-only collection connection");
    expect(empty).not.toHaveTextContent(/connects monitoring providers/);
    expect(screen.getByText(/Guided setup includes permissions, operator commands/)).toBeInTheDocument();
  });

  it("names the configured operator and support address where it does not", async () => {
    const empty = await show(false, served({ operator: "Example Operator", support_email: "help@example.com" }));
    expect(empty).toHaveTextContent(
      "Example Operator connects monitoring providers for this workspace for now. Email help@example.com with the connection name and the Space it belongs in.",
    );
    expect(empty).toHaveTextContent("Never send an API key, client secret or token by email.");
    expect(screen.getByRole("link", { name: "help@example.com" })).toHaveAttribute("href", "mailto:help@example.com");
    expect(empty).not.toHaveTextContent(/Register a read-only/);
    expect(document.body.textContent).not.toMatch(/operator commands|DATABASE_URL|local-data/);
  });

  it("says your service operator, with no link, where the deployment configures neither", async () => {
    const empty = await show(false, ADMIN);
    expect(empty).toHaveTextContent(/Your service operator connects monitoring providers for this workspace for now\.\s*Never send/);
    expect(screen.queryByRole("link")).toBeNull();
  });
});

// Each connection's schedule (MC5, #678): what the server says its intervals are and when the
// scheduled collector next takes it, and that a run holds it now.
describe("the Connections schedule line (MC5)", () => {
  async function card(changes: Parameters<typeof connection>[0]) {
    answerWith({});
    renderPage(withEdition(<Connections data={snapshot({ connections: [connection(changes)] })} />, { operatorCommands: true }), ADMIN);
    await screen.findByText("Platform origin");
  }

  it("names a key-file Tines connection's schedule and when it is next due", async () => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-19T05:00:00+00:00"));
    await card({});
    expect(screen.getByText("Audit records every 15 minutes, inventory daily")).toBeInTheDocument();
    const line = screen.getByText(/Collected on this schedule where the collector holds this connection's key file\./);
    expect(line).toHaveTextContent(/Next due .+\.$/);
    const due = line.querySelector("time");
    expect(due).toHaveAttribute("dateTime", "2026-09-19T05:16:00+00:00");
    expect(screen.queryByText("Collecting now.")).toBeNull();
  });

  it("says since when a connection has been due once its due time has passed", async () => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-19T06:00:00+00:00"));
    await card({});
    const line = screen.getByText(/Collected on this schedule where the collector holds this connection's key file\./);
    expect(line).toHaveTextContent(/Due since .+\.$/);
    expect(line).not.toHaveTextContent(/Next due/);
    expect(line.querySelector("time")).toHaveAttribute("dateTime", "2026-09-19T05:16:00+00:00");
  });

  it("labels the beta sign-in capability and says what the probe found (#355)", async () => {
    await card({
      kind: "entra_agent_id",
      base_url: "https://graph.microsoft.com",
      team_id: null,
      capabilities: {
        audit_log: { state: "available", at: "2026-09-19T05:01:00+00:00" },
        sign_ins: { state: "unlicensed", at: "2026-09-19T05:01:00+00:00" },
      },
    });
    const row = screen.getByText("sign ins (beta)").closest("tr");
    if (row === null) throw new Error("no capability row");
    expect(row).toHaveTextContent("unlicensed");
    expect(screen.getByText("audit log")).toBeInTheDocument();
  });

  it("names an Entra connection's interval in hours", async () => {
    await card({ kind: "entra_agent_id", base_url: "https://graph.microsoft.com", team_id: null, collect_interval_seconds: 21600, activity_interval_seconds: null });
    expect(screen.getByText("Every 6 hours")).toBeInTheDocument();
  });

  it("says a run is collecting now in place of the next due time", async () => {
    await card({ collecting: true });
    expect(screen.getByText("Collecting now.")).toBeInTheDocument();
    expect(screen.queryByText(/Next due/)).toBeNull();
  });

  it("says a sealed connection is overdue on its own schedule", async () => {
    await card({ credential_mode: "sealed", overdue_since: "2026-09-19T05:31:00+00:00", reporting: false });
    expect(screen.getByText(/No collection run has been recorded within twice this connection's interval/)).toBeInTheDocument();
    expect(screen.getByText(/The collector reads it on this schedule\./)).toBeInTheDocument();
    expect(screen.queryByText(/No collection run has been recorded for a day/)).toBeNull();
  });

  it("says when and by whom a directory's consent was last recorded", async () => {
    await card({
      kind: "entra_agent_id",
      credential_mode: "platform_app",
      consented_at: "2026-09-19T04:55:00+00:00",
      consented_by: { principal_id: "0a1b2c3d-0000-4000-8000-000000000009", kind: "ADMIN", label: "Dana Reyes", number: 1 },
    });
    const consent = screen.getByText("Consent recorded").nextElementSibling;
    expect(consent).toHaveTextContent(/^\S.* by Dana Reyes/);
    expect(consent?.querySelector("time")).toHaveAttribute("dateTime", "2026-09-19T04:55:00+00:00");
  });

  it("names no consent for a connection that has none", async () => {
    await card({});
    expect(screen.queryByText("Consent recorded")).toBeNull();
  });

  it("shows no schedule for a revoked connection", async () => {
    await card({ revoked_at: "2026-09-19T06:00:00+00:00", next_due_at: null, reporting: false });
    expect(screen.queryByText(/Collected on this schedule/)).toBeNull();
    expect(screen.queryByText("Audit records every 15 minutes, inventory daily")).toBeNull();
  });
});


// Where console connect is configured (MC17, #678): the deployment's answer, read once and never
// polled, decides whether Tines connects here or the guide's earlier behaviour stands.
describe("connecting from the console where it is configured", () => {
  const CONNECT = "GET /api/console/v1/monitor/connect";
  const available = { body: { tines: "available", entra: "unconfigured" } };

  it("reads whether it can connect once, and opens Connect Tines from the card", async () => {
    const calls = answerWith({ [CONNECT]: available });
    const page = renderPage(withEdition(<Connections data={empty} />, { operatorCommands: false }), ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: "Connect Tines" }));
    expect(await screen.findByRole("dialog", { name: "Connect Tines" })).toBeInTheDocument();
    await settle();
    await settle();
    expect(calls.filter((call) => call.path === "/api/console/v1/monitor/connect")).toHaveLength(1);
    const [query] = page.queryClient.getQueryCache().findAll({ queryKey: [{ _id: "readMonitorConnect" }] });
    const options = query?.options;
    expect((options as { refetchInterval?: unknown } | undefined)?.refetchInterval).toBe(false);
  });

  it("opens Connect Tines from the guided setup where Tines is available", async () => {
    answerWith({ [CONNECT]: available });
    renderPage(withEdition(<Connections data={empty} />, { operatorCommands: false }), ADMIN);
    await settle();
    await userEvent.click(await screen.findByRole("button", { name: "Connect a source" }));
    const guide = await screen.findByRole("dialog", { name: "Connect a source" });
    // Tines connects here, so the guide does not send the reader to an operator for it.
    expect(guide).not.toHaveTextContent(/connects this provider for this workspace/);
    await userEvent.click(within(guide).getByRole("button", { name: "Connect Tines" }));
    expect(await screen.findByRole("dialog", { name: "Connect Tines" })).toBeInTheDocument();
  });

  it("keeps the earlier behaviour where Tines is not configured", async () => {
    answerWith({ [CONNECT]: { body: { tines: "unconfigured", entra: "unconfigured" } } });
    renderPage(withEdition(<Connections data={empty} />, { operatorCommands: false }), ADMIN);
    await settle();
    expect(screen.queryByRole("button", { name: "Connect Tines" })).toBeNull();
    await userEvent.click(await screen.findByRole("button", { name: "Connect a source" }));
    const guide = await screen.findByRole("dialog", { name: "Connect a source" });
    expect(within(guide).queryByRole("button", { name: "Connect Tines" })).toBeNull();
    expect(guide).toHaveTextContent(/connects this provider for this workspace/);
  });

  it("opens Connect Tines from the address where Tines is available", async () => {
    answerWith({ [CONNECT]: available, "GET /api/console/v1/monitor": { body: empty } });
    renderMonitor("/monitor?setup=tines");
    expect(await screen.findByRole("dialog", { name: "Connect Tines" })).toBeInTheDocument();
  });
});

describe("connecting Microsoft Entra and the return from Microsoft (MC11)", () => {
  const CONNECT = "GET /api/console/v1/monitor/connect";
  const options = (last_attempt: unknown = null) => ({
    body: {
      tines: "available",
      entra: "available",
      entra_display_name: "Synthetic Scout",
      entra_client_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
      last_attempt,
    },
  });
  const MADE = "dddddddd-0000-4000-8000-000000000004";

  it("offers Connect Microsoft Entra where it is available, from the card and the address", async () => {
    answerWith({ [CONNECT]: options(), "GET /api/console/v1/monitor": { body: empty } });
    renderMonitor("/monitor");
    await userEvent.click(await screen.findByRole("button", { name: "Connect Microsoft Entra" }));
    expect(await screen.findByRole("dialog", { name: "Connect Microsoft Entra" })).toBeInTheDocument();
    vi.unstubAllGlobals();
    cleanup();
    answerWith({ [CONNECT]: options(), "GET /api/console/v1/monitor": { body: empty } });
    renderMonitor("/monitor?setup=entra_agent_id");
    expect(await screen.findByRole("dialog", { name: "Connect Microsoft Entra" })).toBeInTheDocument();
  });

  it("says Microsoft Entra is connected from the server's record, opens verification and clears the address", async () => {
    answerWith({
      [CONNECT]: options({ outcome: "consented", refused_after_consent: false, connection_id: MADE }),
      "GET /api/console/v1/monitor": { body: empty },
    });
    const { router } = renderMonitor("/monitor?view=connections&connect=done");
    expect(await screen.findByText("Microsoft Entra is connected. The first collection runs within five minutes.")).toBeInTheDocument();
    const guide = await screen.findByRole("dialog", { name: "Connect a source" });
    expect(within(guide).getByLabelText("Connection ID")).toHaveValue(MADE);
    await waitFor(() => {
      expect(router.state.location.search).not.toHaveProperty("connect");
    });
    expect(screen.getByText("Microsoft Entra is connected. The first collection runs within five minutes.")).toBeInTheDocument();
  });

  it.each([
    [false, "The connection was not made, and nothing was created. Start again from Connect Microsoft Entra."],
    [true, "Nothing was created in ExecBound. If you approved access in Microsoft, remove the Synthetic Scout enterprise application from your directory to withdraw it."],
  ])("says what a refusal means, from the server's record, whichever value the address carries (after consent: %s)", async (after, sentence) => {
    for (const value of ["done", "refused"]) {
      vi.unstubAllGlobals();
      cleanup();
      answerWith({
        [CONNECT]: options({ outcome: "refused", refused_after_consent: after, connection_id: null }),
        "GET /api/console/v1/monitor": { body: empty },
      });
      const { router } = renderMonitor(`/monitor?connect=${value}`);
      expect(await screen.findByText(sentence)).toBeInTheDocument();
      expect(screen.queryByText(/Microsoft Entra is connected/)).toBeNull();
      await waitFor(() => {
        expect(router.state.location.search).not.toHaveProperty("connect");
      });
    }
  });

  it("says nothing for a return the server has no record of, and clears the address", async () => {
    answerWith({ [CONNECT]: options(), "GET /api/console/v1/monitor": { body: empty } });
    const { router } = renderMonitor("/monitor?connect=done");
    await waitFor(() => {
      expect(router.state.location.search).not.toHaveProperty("connect");
    });
    await settle();
    expect(screen.queryByText(/Microsoft Entra is connected/)).toBeNull();
    expect(screen.queryByText(/nothing was created/i)).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("reporting sources from the console (MC14, MC16, MC22)", () => {
  const CONNECT = "GET /api/console/v1/monitor/connect";
  const SOURCES = "/api/console/v1/monitor/sources";

  it("offers Add a reporting source only where this deployment mints sources", async () => {
    answerWith({ [CONNECT]: { body: options({ tines: "unconfigured", sources: "unconfigured" }) } });
    renderPage(withEdition(<Connections data={empty} />, { operatorCommands: false }), ADMIN);
    await settle();
    await settle();
    expect(screen.queryByRole("button", { name: "Add a reporting source" })).toBeNull();
    cleanup();
    answerWith({ [CONNECT]: { body: options() } });
    renderPage(withEdition(<Connections data={empty} />, { operatorCommands: false }), ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: "Add a reporting source" }));
    expect(await screen.findByRole("dialog", { name: "Add a reporting source" })).toBeInTheDocument();
  });

  it("waits on the new source's card once its token dialog closes", async () => {
    answerWith({
      [CONNECT]: { body: options() },
      [`POST ${SOURCES}`]: { status: 201, body: minted() },
      [`GET ${SOURCES}/${SOURCE}`]: { body: source() },
    });
    renderPage(withEdition(<Connections data={{ ...empty, sources: [source()] }} />, { operatorCommands: false }), ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: "Add a reporting source" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.type(within(dialog).getByLabelText("Tines story ID"), "4001");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    await userEvent.click(within(shown).getByRole("button", { name: "I have copied it" }));
    const card = (await screen.findByText("Waiting for the first heartbeat from story 4001…")).closest<HTMLElement>(".card");
    expect(card).not.toBeNull();
    expect(card).toHaveTextContent("Disable a user");
  });

  it("says the new source is reporting once the page's snapshot shows its first heartbeat, after the card's ten minutes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    // The card's own reads never see the heartbeat; only the page's snapshot, which polls on its
    // own every 30 seconds, does.
    answerWith({
      [CONNECT]: { body: options() },
      [`POST ${SOURCES}`]: { status: 201, body: minted() },
      [`GET ${SOURCES}/${SOURCE}`]: { body: source() },
    });
    let poll: (data: MonitorSnapshot) => void = () => undefined;
    function Page() {
      const [data, setData] = useState<MonitorSnapshot>({ ...empty, sources: [source()] });
      poll = setData;
      return <Connections data={data} />;
    }
    renderPage(withEdition(<Page />, { operatorCommands: false }), ADMIN);
    await user.click(await screen.findByRole("button", { name: "Add a reporting source" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await user.type(within(dialog).getByLabelText("Tines story ID"), "4001");
    await user.click(within(dialog).getByRole("button", { name: "Create source" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    await user.click(within(shown).getByRole("button", { name: "I have copied it" }));
    expect(await screen.findByText("Waiting for the first heartbeat from story 4001…")).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(11 * 60_000);
    expect(await screen.findByText(/^No heartbeat yet/)).toBeInTheDocument();
    act(() => {
      poll({ ...empty, sources: [source({ coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:12:00+00:00" })] });
    });
    const line = await screen.findByText(/^Reporting\. First heartbeat at/);
    expect(line.closest(".card")).toHaveTextContent("Disable a user");
    expect(line.querySelector("time")).toHaveAttribute("dateTime", "2026-10-12T12:12:00+00:00");
    expect(screen.queryByText(/No heartbeat yet/)).toBeNull();
  });

  it("offers each source's Revoke whether or not this deployment mints sources, and Rotate only where it does", async () => {
    answerWith({ [CONNECT]: { body: options({ tines: "unconfigured", sources: "unconfigured" }) } });
    renderPage(withEdition(<Connections data={{ ...empty, sources: [source()] }} />, { operatorCommands: false }), ADMIN);
    await settle();
    await settle();
    expect(await screen.findByRole("button", { name: "Revoke" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rotate token" })).toBeNull();
  });
});
