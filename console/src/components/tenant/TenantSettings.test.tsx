// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Settings, SignInView, TenantSettingsView } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { Definition } from "../ui/Definitions";
import { TenantSettings } from "./TenantSettings";

const ADMIN = "0a1b2c3d-0000-4000-8000-000000000009";

function view(changes: Partial<TenantSettingsView> = {}): TenantSettingsView {
  return {
    tenant_id: "7f8e9d0c-0000-4000-8000-000000000003",
    tenant_name: "Synthetic SOC",
    mode: { value: "ENFORCE", changed: null },
    deadline: { seconds: 120, bounds: { min: 120, max: 3600 }, changed: null },
    stop: null,
    bundle_id: "3446c357-35fe-4b4c-9911-af20f40e0445",
    monitoring: { sources: 2, reporting: 1, stale: 1, overdue: 0, open_findings: 3 },
    destinations: [
      { destination_id: "soc", kind: "webhook", host: "alerts.example.net", approvers: null, messages: ["pending", "closed"] },
      { destination_id: "oncall", kind: "slack", host: "hooks.slack.com", approvers: 2, messages: ["pending"] },
    ],
    delivery: { window_days: 7, delivered: 6, median_seconds: 40, p90_seconds: 90, slowest_seconds: 95, lapsed: 1, failed: 0 },
    approval_windows: [],
    ...changes,
  };
}

const TENANT = "/api/console/v1/tenant";
const SIGN_IN = "/api/console/v1/tenant/sign-in";
const ASSISTANT = "/api/console/v1/assistant/settings";

/** A workspace administrator: the one who changes the settings that apply to every space. */
const WORKSPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide", "access.manage", "workspace.manage"],
};

/**
 * An administrator seated as `ADMIN` in one space: an administrator, without the workspace-wide
 * `access.manage` that changing a workspace-wide setting takes.
 */
const SPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide"],
};

const STOP = {
  stop_id: "e1e1e1e1-0000-4000-8000-000000000004",
  stopped_at: "2026-09-19T06:10:00+00:00",
  stopped_by: "0a1b2c3d-0000-4000-8000-000000000009",
  reason: "Contain agent 7",
  committed: 0,
  stopped_by_ref: { principal_id: "0a1b2c3d-0000-4000-8000-000000000009", kind: "ADMIN" as const, label: null, number: 1 },
};

const SWITCH: Settings = {
  enabled: true,
  model: "claude-sonnet-5",
  provider_retention: "The provider keeps nothing.",
  person_hourly_turns: 50,
  tenant_daily_tokens: 200000,
};

/** Every control on the page that changes a setting of the whole workspace. */
const CONTROLS = [
  "Change mode",
  "Change deadline",
  "Activate the emergency stop",
  "Resume the tenant",
  "Turn the assistant on",
  "Turn the assistant off",
];

function signIn(changes: Partial<SignInView> = {}): SignInView {
  return {
    configured: true,
    redirect_uri: "https://app.example/login/directory/callback",
    sign_in_url: null,
    invite_url: "https://app.example/invite",
    subject_claims: ["sub", "oid"],
    provider: null,
    ...changes,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

async function openDialog(name: string) {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name }));
  return { user, dialog: await screen.findByRole("dialog") };
}

describe("the tenant settings page", () => {
  it("puts the edition's definitions after the active bundle, and asks for no sandbox (#496)", async () => {
    const seen = answerWith({ [`GET ${TENANT}`]: { body: view() }, [`GET ${SIGN_IN}`]: { body: signIn() } });
    renderPage(withEdition(<TenantSettings />, { TenantDefinitions: () => <Definition term="Edition record">Slot 7</Definition> }));
    const term = await screen.findByText("Edition record", { selector: "dt" });
    const bundle = screen.getByText("Active bundle", { selector: "dt" });
    const monitoring = screen.getByText("Monitoring", { selector: "dt" });
    expect(bundle.compareDocumentPosition(term) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(term.compareDocumentPosition(monitoring) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(seen.some((request) => request.path.endsWith("/tenant/sandbox"))).toBe(false);
  });

  it("shows the mode, the deadline, the stop and the read-only block with destinations as id, kind and host", async () => {
    answerWith({ [`GET ${TENANT}`]: { body: view() }, [`GET ${SIGN_IN}`]: { body: signIn() } });
    renderPage(<TenantSettings />);
    expect(await screen.findByText("Enforcing")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("Workspace settings");
    expect(screen.getByText("120 s")).toBeInTheDocument();
    expect(screen.getByText("Not active")).toBeInTheDocument();
    expect(screen.getByText("3446c357")).toHaveAttribute("href", "/policy");
    expect(screen.getByText(/2 sources: 1 reporting, 1 stale/)).toBeInTheDocument();
    const table = screen.getByRole("table", { name: /notification destinations/ });
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(within(table).getByText("alerts.example.net")).toBeInTheDocument();
    expect(within(table).getByText("every approver")).toBeInTheDocument();
    expect(within(table).getByText("2")).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("https://");
  });

  it("names each destination's messages and says how fast notifications arrived (#678)", async () => {
    const audit = { destination_id: "audit", kind: "security-events", host: "siem.example.net", approvers: 1, messages: [] };
    answerWith({
      [`GET ${TENANT}`]: { body: view({ destinations: [...view().destinations, audit] }) },
      [`GET ${SIGN_IN}`]: { body: signIn() },
    });
    renderPage(<TenantSettings />);
    const table = await screen.findByRole("table", { name: /notification destinations/ });
    expect(within(table).getByRole("columnheader", { name: "Messages" })).toBeInTheDocument();
    expect(within(table).getByText("New requests, Outcomes")).toBeInTheDocument();
    expect(within(table).getByText("New requests")).toBeInTheDocument();
    expect(within(table).getByText("Audit export")).toBeInTheDocument();
    const line = screen.getByText(/^Last 7 days: 6 notifications delivered\./);
    expect(line).toHaveTextContent(
      "Last 7 days: 6 notifications delivered. Half arrived within 40 s, nine in ten within 90 s. 1 not sent because the approval would have lapsed before it arrived.",
    );
    expect(line).toHaveClass("muted");
    // Under the table, before the sentence about who changes destinations.
    expect(table.compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(line.nextElementSibling).toHaveTextContent(/^Destinations are operator configuration/);
  });

  it("shows where approvals are announced inside Approval readiness, not in What this tenant is (#678)", async () => {
    answerWith({ [`GET ${TENANT}`]: { body: view() }, [`GET ${SIGN_IN}`]: { body: signIn() } });
    renderPage(<TenantSettings />);
    const table = await screen.findByRole("table", { name: /notification destinations/ });
    const readiness = screen.getByRole("heading", { name: "Approval readiness" }).closest("section");
    const about = screen.getByRole("heading", { name: "What this tenant is" }).closest("section");
    expect(readiness?.contains(table)).toBe(true);
    expect(about?.contains(table)).toBe(false);
    expect(screen.queryByRole("heading", { name: "Approval deadline" })).toBeNull();
  });

  it("adds no delivery line where nothing announces approvals", async () => {
    answerWith({
      [`GET ${TENANT}`]: {
        body: view({ destinations: [{ destination_id: "audit", kind: "security-events", host: "siem.example.net", approvers: null, messages: [] }] }),
      },
      [`GET ${SIGN_IN}`]: { body: signIn() },
    });
    renderPage(<TenantSettings />);
    expect(await screen.findByText("Audit export")).toBeInTheDocument();
    expect(screen.queryByText(/notifications delivered/)).toBeNull();
    expect(screen.queryByText(/No notifications delivered/)).toBeNull();
  });

  it("hands the deadline dialog the destinations and the measurement, and warns as the deadline is typed", async () => {
    answerWith({ [`GET ${TENANT}`]: { body: view() }, [`GET ${SIGN_IN}`]: { body: signIn() } });
    renderPage(<TenantSettings />, WORKSPACE_ADMINISTRATOR);
    const { user, dialog } = await openDialog("Change deadline");
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    expect(field).toHaveAccessibleDescription(/Nine in ten notifications here arrived within 90 s over the last 7 days\. A deadline under 5 min/);
    await user.clear(field);
    await user.type(field, "600");
    expect(within(dialog).queryByText(/Nine in ten/)).toBeNull();
  });

  it("changes the mode with a reason after a confirmation, and refreshes the session", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view() },
      [`POST ${TENANT}/mode`]: (request) => ({
        body: view({
          mode: {
            value: (request.body as { mode: "ENFORCE" | "OBSERVE" }).mode,
            changed: { at: "2026-09-19T06:00:00+00:00", by: ADMIN, by_ref: { principal_id: ADMIN, kind: "ADMIN", label: null, number: 1 } },
          },
        }),
      }),
      "GET /api/console/v1/session": { body: {} },
    });
    renderPage(<TenantSettings />, WORKSPACE_ADMINISTRATOR);
    const { user, dialog } = await openDialog("Change mode");
    expect(within(dialog).getByRole("combobox", { name: "Mode" })).toHaveValue("OBSERVE");
    // Nothing is sent without a reason.
    await user.click(within(dialog).getByRole("button", { name: "Change mode" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "A reason of 1 to 500 characters is required, with nothing in it that looks like a password, key or token.",
    );
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
    await user.type(within(dialog).getByRole("textbox", { name: /Reason/ }), "  Onboarding trial ");
    await user.click(within(dialog).getByRole("button", { name: "Change mode" }));
    expect(await screen.findByText("Observe only")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.body).toEqual({ mode: "OBSERVE", reason: "Onboarding trial" });
    expect(posted[0]?.headers.get("x-csrf-token")).toBe("token-under-test");
    expect(screen.getByText(/Changed/)).toHaveTextContent("2026-09-19 06:00 UTC by User 1.");
    expect(screen.getByRole("status")).toHaveTextContent("Mode changed to Observe only.");
  });

  it("sends the deadline as typed and shows the bound the server refuses it with", async () => {
    const seen = answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view() },
      [`POST ${TENANT}/deadline`]: (request) => {
        const typed = (request.body as { deadline: string }).deadline;
        return typed === "off" || typed === "600"
          ? { body: view({ deadline: { seconds: typed === "off" ? null : 600, bounds: { min: 120, max: 3600 }, changed: null } }) }
          : { status: 400, body: { code: "INVALID_BODY", detail: "x", fields: ["deadline"] } };
      },
    });
    renderPage(<TenantSettings />, WORKSPACE_ADMINISTRATOR);
    const { user, dialog } = await openDialog("Change deadline");
    const field = within(dialog).getByRole("textbox", { name: /Seconds/ });
    expect(field).toHaveValue("120");
    await user.type(within(dialog).getByRole("textbox", { name: /Reason/ }), "Try");
    for (const bad of ["119", "3601", "soon"]) {
      await user.clear(field);
      await user.type(field, bad);
      await user.click(within(dialog).getByRole("button", { name: "Change deadline" }));
      expect(await within(dialog).findByRole("alert")).toHaveTextContent("The deadline is 120 to 3600 seconds, or off.");
      expect(field).toHaveAttribute("aria-invalid", "true");
    }
    expect(seen.filter((request) => request.method === "POST").map((request) => request.body)).toEqual([
      { deadline: "119", reason: "Try" },
      { deadline: "3601", reason: "Try" },
      { deadline: "soon", reason: "Try" },
    ]);
    expect(screen.getByText("120 s")).toBeInTheDocument();
    await user.clear(field);
    await user.type(field, "off");
    await user.click(within(dialog).getByRole("button", { name: "Change deadline" }));
    expect(await screen.findByText("off")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("turned off");
  });

  it("activates the stop with a reason and shows a conflict as the server's sentence", async () => {
    let stopped = false;
    answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view() },
      [`POST ${TENANT}/stop`]: (request) => {
        if (stopped) return { status: 409, body: { code: "CONFLICT", detail: "x" } };
        stopped = true;
        return {
          body: view({
            stop: {
              stop_id: "e1e1e1e1-0000-4000-8000-000000000004",
              stopped_at: "2026-09-19T06:10:00+00:00",
              stopped_by: ADMIN,
              reason: (request.body as { reason: string }).reason,
              committed: 2,
              stopped_by_ref: { principal_id: ADMIN, kind: "ADMIN", label: null, number: 1 },
            },
          }),
        };
      },
      [`POST ${TENANT}/resume`]: { body: view() },
    });
    renderPage(<TenantSettings />, WORKSPACE_ADMINISTRATOR);
    const { user, dialog } = await openDialog("Activate the emergency stop");
    await user.type(within(dialog).getByRole("textbox", { name: "Reason for stopping" }), "Contain <b>agent 7</b>");
    await user.click(within(dialog).getByRole("button", { name: "Activate the emergency stop" }));
    expect(await screen.findByText("Stop active")).toBeInTheDocument();
    expect(screen.getByText("Reason: Contain <b>agent 7</b>")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(screen.getByText(/2 committed dispatches recorded at activation/)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Emergency stop active.");
    const resume = await openDialog("Resume the tenant");
    await resume.user.type(within(resume.dialog).getByRole("textbox", { name: "Reason for resuming" }), "Reviewed");
    await resume.user.click(within(resume.dialog).getByRole("button", { name: "Resume the tenant" }));
    expect(await screen.findByText("Not active")).toBeInTheDocument();
  });

  it("keeps a refused change in its dialog with the code's copy", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view() },
      [`POST ${TENANT}/stop`]: { status: 409, body: { code: "CONFLICT", detail: "server" } },
    });
    renderPage(<TenantSettings />, WORKSPACE_ADMINISTRATOR);
    const { user, dialog } = await openDialog("Activate the emergency stop");
    await user.type(within(dialog).getByRole("textbox", { name: "Reason for stopping" }), "Twice");
    await user.click(within(dialog).getByRole("button", { name: "Activate the emergency stop" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("already the current state");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Not active")).toBeInTheDocument();
  });

  it("shows a space administrator every setting and the stop in force, with no control to change one", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view({ mode: { value: "OBSERVE", changed: null }, stop: STOP }) },
      [`GET ${ASSISTANT}`]: { body: SWITCH },
    });
    renderPage(<TenantSettings />, { ...SPACE_ADMINISTRATOR, assistant: true });
    // What their own work depends on reading is all there.
    expect(await screen.findByText("Stop active")).toBeInTheDocument();
    expect(screen.getByText("Reason: Contain agent 7")).toBeInTheDocument();
    expect(screen.getByText("Observe only")).toBeInTheDocument();
    expect(screen.getByText("120 s")).toBeInTheDocument();
    expect(await screen.findByText("On")).toBeInTheDocument();
    for (const name of CONTROLS) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    for (const what of [
      "changes the enforcement mode",
      "changes the approval deadline",
      "activates or lifts the emergency stop",
      "turns the assistant on or off",
    ]) {
      expect(screen.getByText(`Only a workspace administrator ${what}, because it applies to every space.`)).toBeInTheDocument();
    }
  });

  it("offers a workspace administrator every control, the stop's as its resume", async () => {
    answerWith({
      [`GET ${SIGN_IN}`]: { body: signIn() },
      [`GET ${TENANT}`]: { body: view({ stop: STOP }) },
      [`GET ${ASSISTANT}`]: { body: SWITCH },
    });
    renderPage(<TenantSettings />, { ...WORKSPACE_ADMINISTRATOR, assistant: true });
    expect(await screen.findByRole("button", { name: "Resume the tenant" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change mode" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Change deadline" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Turn the assistant off" })).toBeInTheDocument();
    expect(screen.queryByText(/Only a workspace administrator/)).toBeNull();
  });
});
