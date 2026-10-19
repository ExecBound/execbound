// SPDX-License-Identifier: AGPL-3.0-only
// Scout's to-do list (#355, step 4): the Agents view in the server's order with what each actor
// did, its driver, its open paths and what to do about it; Accept and Withdraw; the driver card;
// the synthetic directory, labelled wherever it is shown; and a Tines tenant's egress form.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MonitorAgentRow, MonitorReach } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { ADMIN, renderMonitor } from "../../test/monitor";
import { AGENT, agentDetail, agents, connection, OBSERVED, snapshot } from "../../test/monitor-data";
import { answerWith, renderPage, type Seen } from "../../test/page";
import { StepUpHost } from "../StepUpHost";
import { AcceptDialog } from "./AcceptDialog";
import { AgentDetailPage } from "./AgentDetailPage";
import { didWords } from "./Agents";
import { ENTRA_ENTERPRISE_APPS } from "./connect";
import { FindingRow } from "./FindingRow";

const AGENTS = "GET /api/console/v1/monitor/agents";
const DETAIL = `GET /api/console/v1/monitor/agents/${AGENT}`;
const ACCEPT = `POST /api/console/v1/monitor/agents/${AGENT}/accept`;
const WITHDRAW = `POST /api/console/v1/monitor/agents/${AGENT}/withdraw`;
const SNAPSHOT = "GET /api/console/v1/monitor";
const CONNECT = "GET /api/console/v1/monitor/connect";
const ENTRA = {
  body: {
    tines: "available",
    entra: "available",
    entra_display_name: "Synthetic Scout",
    entra_client_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
    last_attempt: null,
  },
};
const APP = "a1a1a1a1-0000-4000-8000-000000000001";
const VERIFY = "POST /api/console/v1/session/verify";
const STALE = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

function nth(elements: HTMLElement[], index: number): HTMLElement {
  const found = elements[index];
  if (found === undefined) throw new Error(`No element ${String(index)}`);
  return found;
}

function row(changes: Partial<MonitorAgentRow>): MonitorAgentRow {
  const [first] = agents.agents;
  if (first === undefined) throw new Error("fixture");
  return { ...first, ...changes };
}

function reach(changes: Partial<MonitorReach> = {}): MonitorReach {
  return {
    action: "identity.disable",
    path_kind: "grant",
    path_ref: "sp-path-1",
    certainty: "inferred",
    effective: "inferred",
    enforcement_mode: "unknown",
    catalog_version: "grants.1",
    valid_until: "2026-10-25T05:00:00+00:00",
    gone_at: null,
    reason_code: null,
    accepted_at: null,
    expires_at: null,
    accepted_by_ref: null,
    accepted: false,
    open: true,
    ...changes,
  };
}

describe("the Agents view, the to-do list", () => {
  it("lists actors in the server's order with what each did, its driver and its open paths", async () => {
    const acted = row({
      agent_id: "aaaaaaaa-0000-4000-8000-0000000000a1",
      display_name: "Offboarding automation",
      identity_class: "service_principal",
      did: 8,
      did_at_least: true,
      open_paths: 1,
      driver: { evidence: "network", kind: "egress", label: "Anthropic" },
      drivers_more: 1,
      removal: "entra",
      app_ref: APP,
    });
    const open = row({ display_name: "Reporting script", identity_class: "consented_app", open_paths: 2 });
    answerWith({ [AGENTS]: { body: { ...agents, agents: [acted, open] } } });
    renderMonitor("/monitor?view=agents");
    const first = (await screen.findByText("Offboarding automation")).closest("tr");
    const second = screen.getByText("Reporting script").closest("tr");
    if (first === null || second === null) throw new Error("No rows");
    expect(first.compareDocumentPosition(second) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(first).getByText("At least 8")).toBeInTheDocument();
    expect(within(first).getByText("Anthropic, seen in its sign-ins")).toBeInTheDocument();
    expect(within(first).getByText("and 1 more")).toBeInTheDocument();
    expect(within(second).getByText("Unattributed")).toBeInTheDocument();
    expect(within(second).getByText("Consented app")).toBeInTheDocument();
    expect(within(second).getByText("2 open paths")).toBeInTheDocument();
    const remove = within(first).getByRole("link", { name: "Remove in Entra" });
    expect(remove).toHaveAttribute("href", ENTRA_ENTERPRISE_APPS);
    expect(remove).toHaveAttribute("rel", "noopener noreferrer");
    expect(first).toHaveTextContent(APP);
    expect(within(first).getByRole("link", { name: "Govern this action" })).toHaveAttribute("href", "/policy");
    expect(screen.getByText(/By source: Microsoft Entra 1, Tines 0/)).toBeInTheDocument();
  });

  it("words a joined driver as the Tines tenant's stories that use a Microsoft credential, never one story", async () => {
    const joined = row({
      display_name: "Joined principal",
      driver: { evidence: "joined", kind: "tines", label: "Tines production" },
      tines_driven: true,
    });
    answerWith({ [AGENTS]: { body: { ...agents, agents: [joined] } } });
    renderMonitor("/monitor?view=agents");
    const found = (await screen.findByText("Joined principal")).closest("tr");
    if (found === null) throw new Error("No row");
    expect(
      within(found).getByText(
        "Tines production, stories that use a credential allowed to call Microsoft Graph or Microsoft sign-in",
      ),
    ).toBeInTheDocument();
    expect(found).not.toHaveTextContent(/Graph credential/);
  });

  it("offers Accept only where the reader may accept, and says where it is done", async () => {
    const theirs = row({ display_name: "Another Space's actor", open_paths: 2, administered: false });
    answerWith({ [AGENTS]: { body: { ...agents, agents: [theirs] } } });
    renderMonitor("/monitor?view=agents");
    const found = (await screen.findByText("Another Space's actor")).closest("tr");
    if (found === null) throw new Error("No row");
    expect(within(found).getByText("2 open paths")).toBeInTheDocument();
    expect(within(found).queryByRole("button", { name: "Accept" })).toBeNull();
    expect(within(found).getByText(/accepted or withdrawn by an administrator of its Space/)).toBeInTheDocument();
  });

  it("says what was done is not assessed without a profile", () => {
    expect(didWords({ did: 3, did_at_least: false }, false)).toBe("Not assessed");
    expect(didWords({ did: 3, did_at_least: false }, true)).toBe("3");
    expect(didWords({ did: 3, did_at_least: true }, true)).toBe("At least 3");
  });

  it("points at the Tines Gate recipe for an actor any Tines row it may see drives, strongest or not", async () => {
    const declared = { evidence: "declared", kind: "publisher", label: "Anthropic" } as const;
    const driven = row({ display_name: "Declared and Tines-driven", driver: declared, drivers_more: 1, tines_driven: true });
    const notDriven = row({
      agent_id: "aaaaaaaa-0000-4000-8000-0000000000a2",
      display_name: "Declared only",
      driver: declared,
      drivers_more: 1,
      tines_driven: false,
    });
    answerWith({ [AGENTS]: { body: { ...agents, agents: [driven, notDriven] } } });
    renderMonitor("/monitor?view=agents");
    const first = (await screen.findByText("Declared and Tines-driven")).closest("tr");
    const second = screen.getByText("Declared only").closest("tr");
    if (first === null || second === null) throw new Error("No rows");
    expect(within(first).getByText("Anthropic, declared by the directory")).toBeInTheDocument();
    expect(within(first).getByText(/follow the Tines Gate recipe/)).toBeInTheDocument();
    expect(within(second).queryByText(/follow the Tines Gate recipe/)).toBeNull();
  });

  it("labels the synthetic directory's actors and offers them no governing", async () => {
    const synthetic = row({ synthetic: true, source: "fixture", removal: null, display_name: "Synthetic triage bot" });
    answerWith({
      [AGENTS]: {
        body: { ...agents, agents: [synthetic], tenant: { ...agents.tenant, per_source: { entra: 0, tines: 0, synthetic: 1 } } },
      },
    });
    renderMonitor("/monitor?view=agents");
    const found = (await screen.findByText("Synthetic triage bot")).closest("tr");
    if (found === null) throw new Error("No row");
    expect(within(found).getByText("Synthetic directory")).toBeInTheDocument();
    expect(within(found).queryByRole("link", { name: "Govern this agent" })).toBeNull();
    expect(within(found).queryByRole("link", { name: "Remove in Entra" })).toBeNull();
    expect(screen.getByRole("note")).toHaveTextContent(/exists only in ExecBound/);
    expect(screen.getByRole("note")).not.toHaveTextContent(/built-in sensitive actions/);
  });

  it("says which list assesses the synthetic directory when no profile is set", async () => {
    const synthetic = row({ synthetic: true, source: "fixture", removal: null, display_name: "Synthetic triage bot" });
    answerWith({
      [AGENTS]: {
        body: {
          ...agents,
          agents: [synthetic],
          consequential: ["identity.disable", "identity.revoke_sessions"],
          tenant: { ...agents.tenant, built_in: true, per_source: { entra: 0, tines: 0, synthetic: 1 } },
        },
      },
    });
    renderMonitor("/monitor?view=agents");
    await screen.findByText("Synthetic triage bot");
    expect(screen.getByRole("note")).toHaveTextContent(
      /No detection profile is set, so they are assessed against the built-in sensitive actions: identity\.disable, identity\.revoke_sessions\./,
    );
  });

  it("asks for a code over Accept, naming the change, and sends it once more", async () => {
    let verified = false;
    const calls = answerWith({
      [DETAIL]: { body: { ...agentDetail(), reach: [reach()] } },
      [ACCEPT]: () => (verified ? { body: agentDetail() } : STALE),
      [VERIFY]: (seen: Seen) => {
        verified = (seen.body as { code: string }).code === "123456";
        return verified ? { body: { csrf_token: "rotated-token" } } : { status: 400, body: { code: "INVALID_FACTOR", detail: "x" } };
      },
    });
    const onClose = vi.fn();
    renderPage(
      <>
        <AcceptDialog agentId={AGENT} name="Payroll agent" onClose={onClose} />
        <StepUpHost />
      </>,
      ADMIN,
    );
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findAllByRole("checkbox");
    await userEvent.selectOptions(within(dialog).getByLabelText("Reason"), "BREAK_GLASS");
    await userEvent.click(within(dialog).getByRole("button", { name: "Accept 1 path" }));
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("To accept an actor's ungoverned paths, confirm it is you.");
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
    expect(calls.filter((call) => `${call.method} ${call.path}` === ACCEPT)).toHaveLength(2);
  });

  it("accepts an actor's open paths for a reason and a period, all chosen", async () => {
    const seen = answerWith({
      [AGENTS]: { body: agents },
      [DETAIL]: { body: { ...agentDetail(), reach: [reach(), reach({ path_ref: "sp-path-2" }), reach({ path_ref: "closed", open: false })] } },
      [ACCEPT]: { body: agentDetail() },
    });
    renderMonitor("/monitor?view=agents");
    await userEvent.click(await screen.findByRole("button", { name: "Accept" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findAllByRole("checkbox")).toHaveLength(2);
    await userEvent.click(within(dialog).getByRole("button", { name: "Accept 2 paths" }));
    expect(await within(dialog).findByText("Choose a reason.")).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText("Reason"), "VENDOR_MANAGED");
    await userEvent.click(nth(within(dialog).getAllByRole("checkbox"), 1));
    await userEvent.click(within(dialog).getByRole("button", { name: "Accept 1 path" }));
    await waitFor(() => {
      expect(seen.some((request) => `${request.method} ${request.path}` === ACCEPT)).toBe(true);
    });
    const sent = seen.find((request) => `${request.method} ${request.path}` === ACCEPT);
    expect(sent?.body).toEqual({
      paths: [{ action: "identity.disable", path_kind: "grant", path_ref: "sp-path-1" }],
      reason_code: "VENDOR_MANAGED",
      days: 90,
    });
  });
});

describe("the agent page", () => {
  it("shows who drives it, the hint as no evidence, and an acceptance with Withdraw and its history", async () => {
    const accepted = reach({
      reason_code: "BREAK_GLASS",
      accepted_at: "2026-10-18T05:00:00+00:00",
      expires_at: "2027-01-16T05:00:00+00:00",
      accepted: true,
      open: false,
    });
    const seen = answerWith({
      [DETAIL]: {
        body: {
          ...agentDetail({ user_agent_hint: "python-requests/2.32.3", user_agent_seen_at: "2026-10-18T08:00:00+00:00" }),
          reach: [accepted, reach({ path_ref: "sp-path-2", reason_code: "LEGACY_CODE", expires_at: "2026-10-01T00:00:00+00:00", open: true })],
          drivers: [
            {
              evidence: "network",
              platform_kind: "egress",
              platform_ref: "egress:anthropic",
              label: "Anthropic",
              source: "https://platform.claude.com/docs/en/api/ip-addresses",
              retrieved: "2026-10-18",
              catalog_version: "egress.2026-10-18",
              story_ids: [],
              stories_capped: false,
              unrestricted_credentials: null,
              first_seen_at: "2026-10-11T08:00:00+00:00",
              last_seen_at: "2026-10-18T08:00:00+00:00",
              gone_at: null,
            },
          ],
          acceptances: [
            {
              change: "accepted",
              action: "identity.disable",
              path_kind: "grant",
              path_ref: "sp-path-1",
              reason_code: "BREAK_GLASS",
              expires_at: "2027-01-16T05:00:00+00:00",
              recorded_by_ref: null,
              recorded_at: "2026-10-18T05:00:00+00:00",
            },
          ],
        },
      },
      [WITHDRAW]: { body: agentDetail() },
    });
    renderPage(<AgentDetailPage agentId={AGENT} />);
    expect(await screen.findByText("Seen in its sign-ins")).toBeInTheDocument();
    expect(screen.getByText(/so this is a hint and not evidence/)).toBeInTheDocument();
    expect(screen.getAllByText("Emergency access").length).toBeGreaterThan(0);
    // A code the command line recorded outside the console's list is shown as it was written.
    expect(screen.getByText("LEGACY_CODE")).toBeInTheDocument();
    expect(screen.getByText("Acceptance expired")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Acceptance history" })).toBeInTheDocument();
    expect(screen.queryByText(/not available in the console yet/)).toBeNull();
    await userEvent.click(nth(screen.getAllByRole("button", { name: "Withdraw" }), 0));
    await userEvent.click(await screen.findByRole("button", { name: "Withdraw acceptance" }));
    await waitFor(() => {
      expect(seen.some((request) => `${request.method} ${request.path}` === WITHDRAW)).toBe(true);
    });
    const sent = seen.find((request) => `${request.method} ${request.path}` === WITHDRAW);
    expect(sent?.body).toEqual({ action: "identity.disable", path_kind: "grant", path_ref: "sp-path-1" });
  });

  it("withdraws an acceptance of an observed path the command line recorded", async () => {
    const observed = reach({
      path_kind: "observation",
      path_ref: "obs-1",
      reason_code: "VENDOR_MANAGED",
      accepted_at: "2026-10-18T05:00:00+00:00",
      expires_at: null,
      accepted: true,
      open: false,
    });
    const seen = answerWith({
      [DETAIL]: { body: { ...agentDetail(), reach: [observed] } },
      [WITHDRAW]: { body: agentDetail() },
    });
    renderPage(<AgentDetailPage agentId={AGENT} />);
    await userEvent.click(await screen.findByRole("button", { name: "Withdraw" }));
    await userEvent.click(await screen.findByRole("button", { name: "Withdraw acceptance" }));
    await waitFor(() => {
      expect(seen.some((request) => `${request.method} ${request.path}` === WITHDRAW)).toBe(true);
    });
    const sent = seen.find((request) => `${request.method} ${request.path}` === WITHDRAW);
    expect(sent?.body).toEqual({ action: "identity.disable", path_kind: "observation", path_ref: "obs-1" });
  });

  it("offers neither Accept nor Withdraw where the reader may not make them", async () => {
    const accepted = reach({
      reason_code: "BREAK_GLASS",
      accepted_at: "2026-10-18T05:00:00+00:00",
      expires_at: "2027-01-16T05:00:00+00:00",
      accepted: true,
      open: false,
    });
    answerWith({
      [DETAIL]: { body: { ...agentDetail({ administered: false }), reach: [accepted, reach({ path_ref: "sp-path-2" })] } },
    });
    renderPage(<AgentDetailPage agentId={AGENT} />);
    expect(await screen.findByText("Accepted")).toBeInTheDocument();
    expect(screen.getAllByText("Open", { selector: "td" }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Accept the open paths" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Withdraw" })).toBeNull();
    expect(screen.getByText(/accepted or withdrawn by an administrator of its Space/)).toBeInTheDocument();
  });

  it("says an actor nothing attributes is unattributed, and a synthetic one cannot be governed", async () => {
    answerWith({ [DETAIL]: { body: agentDetail({ synthetic: true, source: "fixture", removal: null }) } });
    renderPage(<AgentDetailPage agentId={AGENT} />);
    expect(await screen.findByText(/Unattributed: nothing in the directory/)).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent(/synthetic directory, which exists only in ExecBound/);
    expect(screen.queryByRole("heading", { name: "Govern this agent" })).toBeNull();
    expect(screen.getByText("Synthetic directory", { selector: "dd" })).toBeInTheDocument();
  });
});

describe("the synthetic directory and a Tines tenant's egress on Connections", () => {
  const synthetic = connection({
    connection_id: "c0c0c0c0-0000-4000-8000-0000000000f1",
    kind: "fixture",
    credential_mode: "synthetic",
    label: "Synthetic directory",
    base_url: "https://synthetic-directory.invalid",
    team_id: null,
    collect_interval_seconds: 3600,
    activity_interval_seconds: null,
  });

  it("labels the synthetic directory, offers Remove and holds Connect Microsoft Entra", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot({ connections: [synthetic] }) } });
    renderMonitor("/monitor");
    expect(await screen.findByText(/Nothing in it is real/)).toBeInTheDocument();
    expect(screen.getByText("The synthetic directory, read in process from a fixed dataset")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify connection" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Add a synthetic directory" })).toBeNull();
    expect(screen.getByText(/Remove it before connecting Microsoft Entra/)).toBeInTheDocument();
    // Its card says what it is and nothing a real connection's would: no key, no platform API.
    expect(screen.getByText(/from a fixed dataset inside ExecBound with no key and no network/)).toBeInTheDocument();
    expect(screen.queryByText(/read-only key/)).toBeNull();
    expect(screen.queryByText(/fixture-tested/)).toBeNull();
  });

  it("holds Connect Microsoft Entra while the workspace's synthetic directory is in another Space", async () => {
    answerWith({
      [CONNECT]: ENTRA,
      [SNAPSHOT]: { body: snapshot({ connections: [], synthetic_directory: { present: true, addable: false } }) },
    });
    renderMonitor("/monitor");
    expect(await screen.findByRole("button", { name: "Connect Microsoft Entra" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Add a synthetic directory" })).toBeNull();
    expect(screen.getByText(/The workspace's synthetic directory is in another Space/)).toBeInTheDocument();
    expect(screen.queryByText(/A synthetic directory shows what Scout does/)).toBeNull();
  });

  it("offers no synthetic directory where the workspace says none can be added, whatever this Space holds", async () => {
    answerWith({
      [CONNECT]: ENTRA,
      [SNAPSHOT]: { body: snapshot({ connections: [], synthetic_directory: { present: false, addable: false } }) },
    });
    renderMonitor("/monitor");
    expect(await screen.findByRole("button", { name: "Connect Microsoft Entra" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Add a synthetic directory" })).toBeNull();
    expect(screen.queryByText(/A synthetic directory shows what Scout does/)).toBeNull();
  });

  it("offers the synthetic directory to a workspace administrator only, since it holds for every Space", async () => {
    answerWith({ [SNAPSHOT]: { body: snapshot({ connections: [connection({ kind: "tines" })] }) } });
    renderMonitor("/monitor", { session: { ...ADMIN, permissions: ["console.read", "policy.manage", "approvals.decide"] } });
    expect(await screen.findByText(/only a workspace administrator adds it/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a synthetic directory" })).toBeNull();
  });

  it("adds a synthetic directory where no directory was ever connected", async () => {
    const seen = answerWith({
      [SNAPSHOT]: { body: snapshot({ connections: [connection({ kind: "tines" })] }) },
      "POST /api/console/v1/monitor/connections/synthetic": { status: 201, body: synthetic },
    });
    renderMonitor("/monitor");
    await userEvent.click(await screen.findByRole("button", { name: "Add a synthetic directory" }));
    await waitFor(() => {
      expect(seen.some((request) => request.method === "POST" && request.path.endsWith("/connections/synthetic"))).toBe(true);
    });
  });

  it("records a Tines tenant's egress addresses", async () => {
    const tines = connection({ kind: "tines" });
    const seen = answerWith({
      [SNAPSHOT]: { body: snapshot({ connections: [tines] }) },
      [`POST /api/console/v1/monitor/connections/${tines.connection_id}/egress`]: {
        body: { ...tines, egress_addresses: ["18.200.10.20"] },
      },
    });
    renderMonitor("/monitor");
    expect(await screen.findByText("None recorded")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Record egress" }));
    const field = await screen.findByLabelText("Egress addresses");
    await userEvent.type(field, "18.200.10.20");
    await userEvent.click(screen.getByRole("button", { name: "Record addresses" }));
    await waitFor(() => {
      expect(seen.some((request) => request.method === "POST" && request.path.endsWith("/egress"))).toBe(true);
    });
    const sent = seen.find((request) => request.method === "POST" && request.path.endsWith("/egress"));
    expect(sent?.body).toEqual({ addresses: ["18.200.10.20"] });
  });
});

describe("a synthetic directory's finding", () => {
  it("carries the label", async () => {
    renderPage(
      <ul>
        <FindingRow finding={{ ...OBSERVED, synthetic: true }} expanded={false} onToggle={() => undefined} />
      </ul>,
    );
    expect(await screen.findByText("Synthetic directory")).toBeInTheDocument();
  });
});
