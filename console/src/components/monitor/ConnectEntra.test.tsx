// SPDX-License-Identifier: AGPL-3.0-only
// Connect Microsoft Entra (MC8, MC17, #678): the dialog says what is read, who can consent and
// how to withdraw, in the deployment's own app's name; "Continue to Microsoft" posts the start
// and goes to Microsoft's sign-in only when the answer is Microsoft's sign-in address. A refusal
// for a stale factor asks for a code once, naming the change, and sends it again. The state the
// start answers with is kept in no cache, storage or page.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, heldReply, keptNowhere, renderPage, type Seen } from "../../test/page";
import { options, SPACE_A, SPACE_B } from "../../test/source-data";
import { StepUpHost } from "../StepUpHost";
import { leave } from "./connect";
import { ConnectEntra } from "./ConnectEntra";

const START = "/api/console/v1/monitor/connections/entra/start";
const VERIFY = "/api/console/v1/session/verify";
// A distinctive stand-in for the attempt's state, which the console must keep nowhere.
const STATE = "STATE-SENTINEL-entra-start-6d0b2f";
const SIGN_IN = `https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=x&state=${STATE}`;
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", space: { id: SPACE_A, name: "Customer A", archived: false }, spaces: 2 };
const STALE = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };
const CONNECTION = "cccccccc-0000-4000-8000-000000000009";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearToasts();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

function open(connectionId?: string) {
  const onClose = vi.fn();
  const to = vi.spyOn(leave, "to").mockImplementation(() => undefined);
  const rendered = renderPage(
    <>
      <ConnectEntra displayName="Synthetic Scout" connectionId={connectionId} onClose={onClose} />
      <StepUpHost />
    </>,
    ADMIN,
  );
  return { ...rendered, onClose, to };
}

describe("Connect Microsoft Entra (MC8)", () => {
  it("says what is read, who can consent and how to withdraw, before anything is sent", async () => {
    const calls = answerWith({});
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    for (const permission of ["AgentIdentity.Read.All", "Application.Read.All", "AuditLog.Read.All", "Directory.Read.All"]) {
      expect(dialog).toHaveTextContent(permission);
    }
    expect(dialog).toHaveTextContent("nothing that can write");
    expect(dialog).toHaveTextContent("a Global Administrator or Privileged Role Administrator of the directory");
    expect(dialog).toHaveTextContent("remove the Synthetic Scout enterprise application");
    expect(dialog).toHaveTextContent("You will sign in with Microsoft, then approve read-only access. Nothing is created until you approve.");
    expect(dialog).toHaveTextContent("This connection belongs to Customer A.");
    expect(within(dialog).getByLabelText("Connection name")).toHaveValue("Microsoft Entra");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("starts the consent and goes to Microsoft's sign-in, keeping its state nowhere", async () => {
    const calls = answerWith({ [`POST ${START}`]: { body: { authorize_url: SIGN_IN } } });
    const { queryClient, to } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    await userEvent.clear(within(dialog).getByLabelText("Connection name"));
    await userEvent.type(within(dialog).getByLabelText("Connection name"), "Contoso directory");
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue to Microsoft" }));
    await waitFor(() => {
      expect(to).toHaveBeenCalledWith(SIGN_IN);
    });
    expect(calls.filter((call) => call.path === START).map((call) => call.body)).toEqual([{ label: "Contoso directory" }]);
    await keptNowhere(queryClient, STATE);
  });

  it.each([
    "https://evil.example/oauth2/v2.0/authorize",
    "https://login.microsoftonline.com.evil.example/x",
    "http://login.microsoftonline.com/x",
    "javascript:alert(1)",
  ])("treats an address that is not Microsoft's sign-in as unavailable and goes nowhere: %s", async (address) => {
    answerWith({ [`POST ${START}`]: { body: { authorize_url: address } } });
    const { to } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue to Microsoft" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Connecting Microsoft Entra is unavailable right now.");
    expect(to).not.toHaveBeenCalled();
  });

  it("says a refusal in its own words", async () => {
    answerWith({ [`POST ${START}`]: { status: 429, body: { code: "ATTEMPT_CAPACITY", detail: "x" } } });
    const { to } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue to Microsoft" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Too many connection attempts. Try again later.");
    expect(to).not.toHaveBeenCalled();
  });

  it("asks for a code once, naming Connect Microsoft Entra, and starts again", async () => {
    let verified = false;
    const calls = answerWith({
      [`POST ${START}`]: () => (verified ? { body: { authorize_url: SIGN_IN } } : STALE),
      [`POST ${VERIFY}`]: (seen: Seen) => {
        verified = (seen.body as { code: string }).code === "123456";
        return { body: { csrf_token: "rotated-token" } };
      },
    });
    const { to } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue to Microsoft" }));
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("To connect Microsoft Entra, confirm it is you.");
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    await waitFor(() => {
      expect(to).toHaveBeenCalledWith(SIGN_IN);
    });
    expect(calls.filter((call) => call.path === START)).toHaveLength(2);
  });

  it("starts no consent in a Space this administrator only reviews, and says so before any code is asked", async () => {
    const calls = answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: options({ entra: "available", placement: { space_id: SPACE_A, name: "Customer A", archived: false, administered: false } }),
      },
    });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    expect(
      await within(dialog).findByText(
        "You review Customer A but do not administer it, so a connection cannot be added there. Choose a Space you administer.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Continue to Microsoft" })).toBeDisabled();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("starts no consent until it has read where the connection lands, once the session has moved to another Space", async () => {
    const held = heldReply();
    let reads = 0;
    const calls = answerWith({
      // Read while the session was in Customer B; another tab has since moved it to Customer A.
      "GET /api/console/v1/monitor/connect": () => {
        reads += 1;
        return reads === 1
          ? { body: options({ entra: "available", placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }) }
          : held.reply;
      },
      [`POST ${START}`]: { body: { authorize_url: SIGN_IN } },
    });
    const { to } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Microsoft Entra" });
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    expect(dialog).not.toHaveTextContent(/belongs to Customer B/);
    expect(dialog).toHaveTextContent("Checking which Space this lands in…");
    const go = within(dialog).getByRole("button", { name: "Continue to Microsoft" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Connection name"), "{Enter}");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    expect(to).not.toHaveBeenCalled();
    held.send({ body: options({ entra: "available" }) });
    await within(dialog).findByText(/This connection belongs to Customer A\./);
    expect(go).toBeEnabled();
  });

  it("updates a connection's consent without asking for a name", async () => {
    const calls = answerWith({ [`POST ${START}`]: { body: { authorize_url: SIGN_IN } } });
    const { to } = open(CONNECTION);
    const dialog = await screen.findByRole("dialog", { name: "Update consent" });
    expect(within(dialog).queryByLabelText("Connection name")).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue to Microsoft" }));
    await waitFor(() => {
      expect(to).toHaveBeenCalledWith(SIGN_IN);
    });
    expect(calls.filter((call) => call.path === START).map((call) => call.body)).toEqual([{ connection_id: CONNECTION }]);
  });
});
