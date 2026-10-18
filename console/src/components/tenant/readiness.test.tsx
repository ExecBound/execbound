// SPDX-License-Identifier: AGPL-3.0-only
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApprovalWindow, ApprovalWindowSpace, NotificationDestination, TenantSettingsView } from "../../api/types.gen";
import { NO_SERVICE, PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { withEdition } from "../../test/edition";
import { answerWith, renderPage } from "../../test/page";
import { ApprovalReadiness } from "./ApprovalReadiness";

const WORKSPACE_ADMINISTRATOR: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "policy.manage", "approvals.decide", "access.manage", "workspace.manage"],
};

const ISOLATE: ApprovalWindow = {
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  context_seconds: 300,
  bound_seconds: 300,
  limited_by: "context",
  source_kinds: ["incident", "inventory"],
  known: true,
};
const DISABLE: ApprovalWindow = {
  action: "identity.disable",
  action_label: "Disable <b>identity</b>",
  context_seconds: 300,
  bound_seconds: 120,
  limited_by: "deadline",
  source_kinds: ["inventory"],
  known: false,
};

const EMAIL: NotificationDestination = { destination_id: "jane", kind: "email", host: "", approvers: null, messages: ["pending"] };
const AUDIT: NotificationDestination = { destination_id: "audit", kind: "security-events", host: "siem.example.net", approvers: null, messages: [] };

const DEFAULT: ApprovalWindowSpace = {
  space_id: "5a5a5a5a-0000-4000-8000-000000000001",
  name: "Default",
  bundle_id: "3446c357-35fe-4b4c-9911-af20f40e0445",
  actions: [],
};

function view(changes: Partial<TenantSettingsView> = {}): TenantSettingsView {
  return {
    tenant_id: "7f8e9d0c-0000-4000-8000-000000000003",
    tenant_name: "Synthetic SOC",
    mode: { value: "ENFORCE", changed: null },
    deadline: { seconds: 600, bounds: { min: 120, max: 3600 }, changed: null },
    stop: null,
    bundle_id: "3446c357-35fe-4b4c-9911-af20f40e0445",
    monitoring: { sources: 0, reporting: 0, stale: 0, overdue: 0, open_findings: 0 },
    destinations: [],
    delivery: { window_days: 7, delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null, lapsed: 0, failed: 0 },
    approval_windows: [{ ...DEFAULT, actions: [ISOLATE] }],
    ...changes,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

const WARNING = "are announced nowhere but this console. Unless a reviewer is watching Approvals, they lapse.";

/** The warning's paragraph, matched on its whole text: the Approvals link sits inside it. */
function warning(scope: Awaited<ReturnType<typeof card>>) {
  return scope.queryByText((_content, element) => element?.tagName === "P" && element.textContent.includes(WARNING));
}

async function card() {
  const heading = await screen.findByRole("heading", { name: "Approval readiness" });
  const section = heading.closest("section");
  if (section === null) throw new Error("no card");
  return within(section);
}

describe("the approval readiness card (#678, AR10, AR11)", () => {
  it("keeps the deadline, its change line and Change deadline, and states each action's window", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view({ deadline: { seconds: 120, bounds: { min: 120, max: 3600 }, changed: null } })} workspace />, WORKSPACE_ADMINISTRATOR);
    const readiness = await card();
    expect(readiness.getByText("120 s")).toBeInTheDocument();
    expect(readiness.getByText("The default, never changed.")).toBeInTheDocument();
    expect(readiness.getByRole("button", { name: "Change deadline" })).toBeInTheDocument();
    expect(readiness.getByRole("heading", { name: "How long a held request can wait" })).toBeInTheDocument();
    expect(
      readiness.getByText("Isolate endpoint: at most about 5 minutes. Its incident and inventory facts are valid for 5 minutes from when they were recorded."),
    ).toBeInTheDocument();
    expect(readiness.getByText(/^A request can wait less than this: the time starts when the facts were recorded/)).toBeInTheDocument();
  });

  it("says when the deadline is the limit, renders labels as text, and marks what a custom policy may hold", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view({ approval_windows: [{ ...DEFAULT, actions: [DISABLE] }] })} workspace />);
    expect((await card()).getByText("Disable <b>identity</b>: at most 2 minutes, the approval deadline.")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect((await card()).getByText("Custom policy: it may hold this action; which requests it holds cannot be read from the policy.")).toBeInTheDocument();
  });

  it("names each Space where several are listed, says when one has no policy, and when a figure is unknown", async () => {
    answerWith({});
    const unknown: ApprovalWindow = { ...ISOLATE, context_seconds: null, bound_seconds: null, limited_by: "unknown", source_kinds: [] };
    renderPage(
      <ApprovalReadiness
        view={view({
          approval_windows: [
            { space_id: "5a5a5a5a-0000-4000-8000-000000000002", name: "Branch office", bundle_id: null, actions: [] },
            { space_id: "5a5a5a5a-0000-4000-8000-000000000001", name: "Default", bundle_id: "3446c357-35fe-4b4c-9911-af20f40e0445", actions: [unknown] },
          ],
        })}
        workspace
      />,
    );
    const readiness = await card();
    expect(readiness.getByRole("heading", { name: "Branch office" })).toBeInTheDocument();
    expect(readiness.getByRole("heading", { name: "Default" })).toBeInTheDocument();
    expect(readiness.getByText("No active policy: nothing is held.")).toBeInTheDocument();
    expect(readiness.getByText(/^Isolate endpoint: no figure, because its context contract is not in this deployment's catalog\./)).toBeInTheDocument();
  });

  it("warns under Enforce with a short window and no destination, naming both causes, then the operator remedy", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view()} workspace />);
    const readiness = await card();
    const shown = warning(readiness);
    if (shown === null) throw new Error("no warning");
    expect(shown).toHaveTextContent(/^Held requests here wait at most 5 minutes and are announced nowhere but this console\./);
    expect(within(shown).getByRole("link", { name: "Approvals" })).toHaveAttribute("href", "/approvals");
    expect(
      readiness.getByText(
        "Destinations are operator configuration, set in this deployment's private configuration file (see Notifications and webhooks in the operator documentation).",
        { exact: false },
      ),
    ).toBeInTheDocument();
    // No help link where the deployment names no documentation.
    expect(readiness.queryByRole("link", { name: "Open the documentation" })).toBeNull();
  });

  it("gives the help link with the core remedy where the deployment names its documentation", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view()} workspace />, { ...PLACEHOLDER, service: { ...NO_SERVICE, help_url: "https://docs.example.com/" } });
    expect((await card()).getByRole("link", { name: "Open the documentation" })).toHaveAttribute("href", "https://docs.example.com/");
  });

  it("says some requests when only some windows are short", async () => {
    answerWith({});
    const long: ApprovalWindow = { ...ISOLATE, action: "identity.enable", action_label: "Enable identity", context_seconds: 900, bound_seconds: 900 };
    renderPage(<ApprovalReadiness view={view({ approval_windows: [{ ...DEFAULT, actions: [ISOLATE, long] }] })} workspace />);
    expect(warning(await card())).toHaveTextContent(/^Some held requests here wait at most 5 minutes/);
  });

  it("warns the same where the only destination is the audit export", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view({ destinations: [AUDIT] })} workspace />);
    expect(warning(await card())).toBeInTheDocument();
  });

  it.each([
    ["an email destination announces approvals", view({ destinations: [EMAIL] })],
    ["the workspace observes", view({ mode: { value: "OBSERVE", changed: null } })],
    ["every window is ten minutes or more", view({ approval_windows: [{ ...DEFAULT, actions: [{ ...ISOLATE, context_seconds: 600, bound_seconds: 600 }] }] })],
  ])("does not warn where %s", async (_case, given) => {
    answerWith({});
    renderPage(<ApprovalReadiness view={given} workspace />);
    expect(warning(await card())).toBeNull();
    expect((await card()).queryByText(/Destinations are operator configuration, set in/)).toBeNull();
  });

  it("carries the announcements block unchanged", async () => {
    answerWith({});
    renderPage(<ApprovalReadiness view={view({ destinations: [EMAIL, AUDIT] })} workspace />);
    const readiness = await card();
    const table = readiness.getByRole("table", { name: /notification destinations/ });
    expect(within(table).getByText("New requests")).toBeInTheDocument();
    expect(within(table).getByText("Audit export")).toBeInTheDocument();
    expect(readiness.getByText("No notifications delivered in the last 7 days.")).toBeInTheDocument();
    expect(readiness.getByText(/^Destinations are operator configuration; the command line/)).toBeInTheDocument();
  });

  it("uses the edition's remedy where the edition supplies one", async () => {
    answerWith({});
    renderPage(withEdition(<ApprovalReadiness view={view()} workspace />, { ApprovalRemedy: () => <p>Edition remedy</p> }));
    expect((await card()).getByText("Edition remedy")).toBeInTheDocument();
    expect((await card()).queryByText(/Destinations are operator configuration, set in/)).toBeNull();
  });

  it("offers a narrowed administrator no control, and sends nothing as the dialog opens and closes", async () => {
    const seen = answerWith({});
    const { unmount } = renderPage(<ApprovalReadiness view={view()} workspace={false} />);
    expect((await card()).queryByRole("button", { name: "Change deadline" })).toBeNull();
    expect((await card()).getByText("Only a workspace administrator changes the approval deadline, because it applies to every space.")).toBeInTheDocument();
    unmount();
    renderPage(<ApprovalReadiness view={view({ destinations: [EMAIL] })} workspace />, WORKSPACE_ADMINISTRATOR);
    const user = userEvent.setup();
    await user.click((await card()).getByRole("button", { name: "Change deadline" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(seen).toEqual([]);
  });
});
