// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TenantSettingsView } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, type Reply, renderPage, type Seen } from "../../test/page";
import { StepUpHost } from "../StepUpHost";
import { PilotCard } from "./PilotCard";

const MODE = "/api/console/v1/tenant/mode";
const VERIFY = "/api/console/v1/session/verify";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", mode: "ENFORCE" };
const STALE: Reply = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };

function tenant(mode: "ENFORCE" | "OBSERVE"): TenantSettingsView {
  return {
    tenant_id: "7f8e9d0c-0000-4000-8000-000000000003",
    tenant_name: "Synthetic SOC",
    mode: { value: mode, changed: null },
    deadline: { seconds: 120, bounds: { min: 120, max: 3600 }, changed: null },
    stop: null,
    bundle_id: null,
    monitoring: { sources: 0, reporting: 0, stale: 0, overdue: 0, open_findings: 0 },
    delivery: { window_days: 7, delivered: 0, median_seconds: null, p90_seconds: null, slowest_seconds: null, lapsed: 0, failed: 0 },
    approval_windows: [],
    destinations: [],
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

async function change(reason = "Two-week pilot") {
  await userEvent.click(await screen.findByRole("button", { name: "Change the mode" }));
  const dialog = await screen.findByRole("dialog", { name: "Change the enforcement mode?" });
  expect(within(dialog).getByRole("combobox", { name: "Mode" })).toHaveValue("OBSERVE");
  await userEvent.type(within(dialog).getByRole("textbox", { name: /Reason/ }), reason);
  await userEvent.click(within(dialog).getByRole("button", { name: "Change mode" }));
  return dialog;
}

describe("Pilot in Observe only (UX15, #678)", () => {
  it("says a policy is still required, that the mode is workspace-wide and that samples need Enforcing", async () => {
    answerWith({});
    renderPage(<PilotCard />, ADMIN);
    const card = (await screen.findByRole("heading", { name: "Pilot in Observe only (optional)" })).closest("section");
    expect(card).toHaveTextContent("A policy must still be active");
    expect(card).toHaveTextContent("The mode applies to the whole workspace");
    expect(card).toHaveTextContent("needs Enforcing");
    expect(card).toHaveTextContent('Operations, "Onboard a tenant in observe-only mode"');
    expect(screen.getByRole("link", { name: "Review what would have happened" })).toHaveAttribute("href", "/activity?state=OBSERVED");
  });

  it("names the button for the mode the workspace is in, and offers none where the mode is unknown", async () => {
    answerWith({});
    const enforcing = renderPage(<PilotCard />, ADMIN);
    expect(await screen.findByRole("button", { name: "Change the mode" })).toBeInTheDocument();
    enforcing.unmount();
    const observing = renderPage(<PilotCard />, { ...ADMIN, mode: "OBSERVE" });
    expect(await screen.findByRole("button", { name: "Return to Enforcing" })).toBeInTheDocument();
    observing.unmount();
    renderPage(<PilotCard />, { ...ADMIN, mode: "UNKNOWN" });
    expect(await screen.findByText("The current mode could not be read.")).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText(/A policy must still be active/)).toBeInTheDocument();
  });

  it("opens the reasoned mode dialog and waits for the server's answer", async () => {
    let answer: (reply: Reply) => void = () => undefined;
    const seen = answerWith({
      [`POST ${MODE}`]: () => new Promise<Reply>((resolve) => { answer = resolve; }),
    });
    renderPage(<PilotCard />, ADMIN);
    const dialog = await change();
    await waitFor(() => {
      expect(seen.filter((request) => request.method === "POST" && request.path === MODE)).toHaveLength(1);
    });
    expect(seen.find((request) => request.path === MODE)?.body).toEqual({ mode: "OBSERVE", reason: "Two-week pilot" });
    // Nothing changes until the server answers.
    expect(dialog).toBeInTheDocument();
    expect(screen.queryByText("Mode changed to Observe only.")).toBeNull();
    answer({ body: tenant("OBSERVE") });
    expect(await screen.findByText("Mode changed to Observe only.")).toBeInTheDocument();
  });

  it("goes through the step-up the server asks for, and changes nothing until the resent change is answered", async () => {
    let verified = false;
    const seen = answerWith({
      [`POST ${MODE}`]: () => (verified ? { body: tenant("OBSERVE") } : STALE),
      [`POST ${VERIFY}`]: (request: Seen) => {
        verified = (request.body as { code: string }).code === "123456";
        return verified ? { body: { csrf_token: "rotated-token" } } : { status: 400, body: { code: "INVALID_FACTOR", detail: "x" } };
      },
    });
    renderPage(<><PilotCard /><StepUpHost /></>, ADMIN);
    await change();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(screen.queryByText("Mode changed to Observe only.")).toBeNull();
    // The card under the question is as it was: the button still offers the change.
    expect(screen.getByRole("button", { name: "Change the mode", hidden: true })).toBeInTheDocument();
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("Mode changed to Observe only.")).toBeInTheDocument();
    const posts = seen.filter((request) => request.method === "POST" && request.path === MODE);
    expect(posts).toHaveLength(2);
    expect(posts[1]?.body).toEqual(posts[0]?.body);
  });
});
