// SPDX-License-Identifier: AGPL-3.0-only
// A connection's actions (MC12, #678): each card names how its connection authenticates;
// "Collect now" waits for the server and shows what the server answered; Schedule offers each
// kind's fixed choices in every credential mode; Revoke asks first; Replace key is a sealed
// Tines connection's alone.

import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MonitorConnection } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { withEdition } from "../../test/edition";
import { connection, snapshot } from "../../test/monitor-data";
import { answerWith, heldReply, keptNowhere, renderPage, settle } from "../../test/page";
import { Connections } from "./Connections";
import { MonitorPage } from "./MonitorPage";

const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };
const ID = "cccccccc-0000-4000-8000-000000000001";
const PATH = `/api/console/v1/monitor/connections/${ID}`;
const DANA = { principal_id: "0a1b2c3d-0000-4000-8000-000000000009", kind: "ADMIN" as const, label: "Dana Reyes", number: 1 };
const AVAILABLE = { body: { tines: "available", entra: "unconfigured" } };

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

async function card(changes: Partial<MonitorConnection>, routes: Parameters<typeof answerWith>[0] = {}) {
  const calls = answerWith({ "GET /api/console/v1/monitor/connect": AVAILABLE, ...routes });
  const { queryClient } = renderPage(withEdition(<Connections data={snapshot({ connections: [connection({ connection_id: ID, ...changes })] })} />, { operatorCommands: true }), ADMIN);
  await screen.findByText("Platform origin");
  await settle();
  return Object.assign(calls, { queryClient });
}

describe("each connection's credential and actions (MC12)", () => {
  it.each([
    ["sealed", "Key sealed for the collector"],
    ["key_file", "Operator key file"],
  ] as const)("names a %s connection's credential", async (mode, words) => {
    await card({ credential_mode: mode });
    expect(screen.getByText(words)).toBeInTheDocument();
  });

  it("asks for a collection and shows the request only once the server answers it", async () => {
    // The page as it reads the snapshot: the server's state, which the answer changes.
    let current = connection({ connection_id: ID, credential_mode: "sealed" });
    const held = heldReply();
    const calls = answerWith({
      "GET /api/console/v1/monitor/connect": AVAILABLE,
      "GET /api/console/v1/monitor": () => ({ body: snapshot({ connections: [current] }) }),
      [`POST ${PATH}/collect`]: async () => {
        const reply = await held.reply;
        current = reply.body as MonitorConnection;
        return reply;
      },
    });
    renderPage(withEdition(<MonitorPage />, { operatorCommands: true }), ADMIN);
    await screen.findByText("Platform origin");
    await settle();
    await userEvent.click(screen.getByRole("button", { name: "Collect now" }));
    const pending = screen.getByRole("button", { name: "Asking…" });
    expect(pending).toBeDisabled();
    expect(screen.queryByText(/Requested at/)).toBeNull();
    held.send({ body: connection({ connection_id: ID, credential_mode: "sealed", collect_requested_at: "2026-09-19T05:03:00+00:00", collect_requested_by: DANA }) });
    const line = await screen.findByText(/Requested at/);
    expect(line).toHaveTextContent(/by Dana Reyes.+The next scheduled run picks it up within five minutes\./);
    expect(line.querySelector("time")).toHaveAttribute("dateTime", "2026-09-19T05:03:00+00:00");
    expect(calls.filter((call) => call.method === "POST").map((call) => [call.path, call.body])).toEqual([[`${PATH}/collect`, {}]]);
  });

  it("says where an operator's key file is collected once a request is waiting", async () => {
    await card({ credential_mode: "key_file", collect_requested_at: "2026-09-19T05:03:00+00:00", collect_requested_by: DANA });
    expect(screen.getByText("Requested. The collector picks it up where it holds this connection's key file.")).toBeInTheDocument();
  });

  it.each([
    ["tines", ["5 minutes", "15 minutes", "30 minutes", "1 hour"], "30 minutes", { activity_interval_seconds: 1800 }],
    ["entra_agent_id", ["1 hour", "3 hours", "6 hours", "12 hours", "24 hours"], "12 hours", { collect_interval_seconds: 43200 }],
  ] as const)("offers %s its fixed intervals and posts the chosen seconds", async (kind, offered, chosen, body) => {
    const entra = kind === "entra_agent_id";
    const calls = await card(
      entra
        ? { kind, base_url: "https://graph.microsoft.com", team_id: null, collect_interval_seconds: 21600, activity_interval_seconds: null }
        : { kind },
      { [`POST ${PATH}/schedule`]: { body: connection({ connection_id: ID }) } },
    );
    await userEvent.click(screen.getByRole("button", { name: "Schedule" }));
    const dialog = await screen.findByRole("dialog", { name: "Schedule collection" });
    const select = within(dialog).getByRole("combobox");
    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual(offered);
    await userEvent.selectOptions(select, chosen);
    await userEvent.click(within(dialog).getByRole("button", { name: "Save schedule" }));
    await waitFor(() => {
      expect(calls.filter((call) => call.path === `${PATH}/schedule`).map((call) => call.body)).toEqual([body]);
    });
  });

  it("asks before revoking, and revokes only on confirmation", async () => {
    const calls = await card({}, { [`POST ${PATH}/revoke`]: { body: connection({ connection_id: ID, revoked_at: "2026-09-19T06:00:00+00:00", next_due_at: null }) } });
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke this connection?" });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke connection" }));
    await waitFor(() => {
      expect(calls.filter((call) => call.path === `${PATH}/revoke`).map((call) => call.body)).toEqual([{}]);
    });
  });

  it("offers Replace key on a sealed Tines connection alone", async () => {
    await card({ credential_mode: "key_file" });
    expect(screen.queryByRole("button", { name: "Replace key" })).toBeNull();
  });

  it.each([
    ["replaced", { body: connection({ connection_id: ID, credential_mode: "sealed" }) }],
    ["refused", { status: 422, body: { code: "INVALID_BODY", detail: "Request body is invalid." } }],
  ] as const)("replaces a sealed key with a password field and keeps nothing of it once %s", async (_, reply) => {
    const calls = await card({ credential_mode: "sealed" }, { [`POST ${PATH}/key`]: reply });
    await userEvent.click(screen.getByRole("button", { name: "Replace key" }));
    const dialog = await screen.findByRole("dialog", { name: "Replace the key" });
    const field = within(dialog).getByLabelText("New API key");
    expect(field).toHaveAttribute("type", "password");
    await userEvent.type(field, "SENTINEL-replacement-key");
    await userEvent.click(within(dialog).getByRole("button", { name: "Replace key" }));
    await waitFor(() => {
      expect(calls.filter((call) => call.path === `${PATH}/key`).map((call) => call.body)).toEqual([{ api_key: "SENTINEL-replacement-key" }]);
    });
    // In no query or mutation record, no browser storage and nowhere in the document, as
    // Connect Tines holds its own key.
    await keptNowhere(calls.queryClient, "SENTINEL-replacement-key");
  });

  it("shows no action on a revoked connection", async () => {
    await card({ revoked_at: "2026-09-19T06:00:00+00:00", next_due_at: null, reporting: false });
    expect(screen.queryByRole("button", { name: "Collect now" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });
});

describe("a consented Microsoft Entra connection (MC11, MC12)", () => {
  const ENTRA = { body: { tines: "available", entra: "available", entra_display_name: "Synthetic Scout", entra_client_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", last_attempt: null } };
  const consented = {
    kind: "entra_agent_id" as const,
    base_url: "https://graph.microsoft.com",
    credential_mode: "platform_app" as const,
    collect_interval_seconds: 21600,
    activity_interval_seconds: null,
    consented_at: "2026-09-19T05:00:00+00:00",
    consented_by: DANA,
  };

  it("names its credential as an admin consent", async () => {
    await card(consented, { "GET /api/console/v1/monitor/connect": ENTRA });
    expect(screen.getByText("Admin consent")).toBeInTheDocument();
  });

  it("offers Update consent only once a permission it had is refused", async () => {
    await card(consented, { "GET /api/console/v1/monitor/connect": ENTRA });
    expect(screen.queryByRole("button", { name: "Update consent" })).toBeNull();
    expect(screen.queryByText(/Consent needs updating/)).toBeNull();
    vi.unstubAllGlobals();
    cleanup();
    await card({ ...consented, consent_needs_update: true }, { "GET /api/console/v1/monitor/connect": ENTRA });
    expect(screen.getByText("Consent needs updating: a permission this connection had is now refused.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Update consent" }));
    expect(await screen.findByRole("dialog", { name: "Update consent" })).toBeInTheDocument();
  });

  it("says how to withdraw the directory's consent when revoking, naming the deployment's app", async () => {
    await card(consented, { "GET /api/console/v1/monitor/connect": ENTRA });
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke this connection?" });
    expect(dialog).toHaveTextContent(
      "Revoking stops collection here. To withdraw this deployment's access to your directory, remove the Synthetic Scout enterprise application (client ID 0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d) in Microsoft Entra.",
    );
    const link = within(dialog).getByRole("link", { name: /Enterprise applications in the Microsoft Entra admin center/ });
    expect(link).toHaveAttribute("href", "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("shows who asked once a request waits, as for a sealed key", async () => {
    await card({ ...consented, collect_requested_at: "2026-09-19T05:10:00+00:00", collect_requested_by: DANA }, { "GET /api/console/v1/monitor/connect": ENTRA });
    expect(screen.getByText(/The next scheduled run picks it up within five minutes/)).toHaveAttribute("role", "status");
  });
});
