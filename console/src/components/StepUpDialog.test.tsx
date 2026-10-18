// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AccessPage } from "../api/types.gen";
import { clearToasts } from "../lib/toast";
import { answerWith, settle, type Seen } from "../test/page";
import { InviteTeammate } from "./directory/InviteTeammate";
import { StepUpHost } from "./StepUpHost";
import { Toaster } from "./ui/Toast";

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
  Reflect.deleteProperty(navigator, "credentials");
});

const INVITE = "/api/console/v1/teammate-invitations";
const VERIFY = "/api/console/v1/session/verify";
const ACCESS: AccessPage = {
  roles: [{ id: "viewer", name: "Viewer", description: "Read activity", permissions: [], scopes: ["WORKSPACE", "SPACE"] }],
  spaces: [],
  groups: [],
  users: [],
};
const STALE = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };
const WRONG = { status: 400, body: { code: "INVALID_FACTOR", detail: "That code could not be used." } };

function mount(element: ReactNode) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      {element}
      <StepUpHost />
      <Toaster />
    </QueryClientProvider>,
  );
}

/** Answers the invitation with MFA_REQUIRED until a code was accepted, then creates it. */
function workspace(codes: Record<string, "wrong" | "right">) {
  let verified = false;
  const calls = answerWith({
    "GET /api/console/v1/access": { body: ACCESS },
    [`POST ${INVITE}`]: () => (verified ? { body: { invitation_id: "x", expires_at: "2030-01-01T00:00:00Z" } } : STALE),
    [`POST ${VERIFY}`]: (seen: Seen) => {
      const code = (seen.body as { code: string }).code;
      if (codes[code] !== "right") return WRONG;
      verified = true;
      return { body: { csrf_token: "rotated-token" } };
    },
  });
  return calls;
}

async function invite() {
  await userEvent.click(screen.getByRole("button", { name: "Invite teammate" }));
  const dialog = await screen.findByRole("dialog", { name: "Invite a teammate" });
  await userEvent.type(within(dialog).getByLabelText("Email"), "new@example.org");
  await userEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
  return dialog;
}

describe("the step-up asked in place", () => {
  it("asks over the open dialog, says a wrong code is wrong, and finishes the change once", async () => {
    const calls = workspace({ "123456": "right" });
    mount(<InviteTeammate />);
    const inviting = await invite();

    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    // What the person typed is still there, under the question.
    expect(within(inviting).getByLabelText("Email")).toHaveValue("new@example.org");
    const field = within(asking).getByLabelText("Authentication code");
    await waitFor(() => { expect(field).toHaveFocus(); });

    await userEvent.type(field, "000000");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    expect(await within(asking).findByRole("alert")).toHaveTextContent("That code could not be used.");
    expect(screen.getByRole("dialog", { name: "Verify your identity" })).toBeInTheDocument();

    await userEvent.type(within(asking).getByLabelText("Authentication code"), " 123 456 ");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    expect(await screen.findByText(/Invitation queued\./)).toBeInTheDocument();
    await waitFor(() => { expect(screen.queryByRole("dialog")).not.toBeInTheDocument(); });

    const verifications = calls.filter((call) => call.path === VERIFY);
    expect(verifications.map((call) => call.body)).toEqual([{ code: "000000" }, { code: "123456" }]);
    expect(verifications.every((call) => call.headers.get("X-CSRF-Token") === "token-under-test")).toBe(true);
    const invitations = calls.filter((call) => call.path === INVITE && call.method === "POST");
    expect(invitations).toHaveLength(2);
    expect(invitations[0]?.headers.get("X-CSRF-Token")).toBe("token-under-test");
    expect(invitations[1]?.headers.get("X-CSRF-Token")).toBe("rotated-token");
    expect(invitations[1]?.body).toEqual(invitations[0]?.body);
  });

  it("leaves the dialog and what was typed when the person cancels, and says the change was not made", async () => {
    const calls = workspace({});
    mount(<InviteTeammate />);
    const inviting = await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await userEvent.click(within(asking).getByRole("button", { name: "Cancel" }));
    await waitFor(() => { expect(screen.queryByRole("dialog", { name: "Verify your identity" })).not.toBeInTheDocument(); });
    expect(await within(inviting).findByRole("alert")).toHaveTextContent("This change was not made.");
    expect(within(inviting).getByLabelText("Email")).toHaveValue("new@example.org");
    expect(within(inviting).getByRole("button", { name: "Invite" })).toBeEnabled();
    expect(calls.filter((call) => call.path === INVITE && call.method === "POST")).toHaveLength(1);
    expect(calls.filter((call) => call.path === VERIFY)).toHaveLength(0);
  });

  it("asks for a code before sending nothing", async () => {
    const calls = workspace({});
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    expect(await within(asking).findByRole("alert")).toHaveTextContent("Enter a code");
    expect(calls.filter((call) => call.path === VERIFY)).toHaveLength(0);
  });
});

describe("the step-up's purpose line (SU11)", () => {
  it("names the refused change and says one verification covers others", async () => {
    workspace({});
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("To invite a teammate, confirm it is you.");
    expect(asking).toHaveTextContent("Verification lasts thirty minutes and covers other protected changes.");
    expect(within(asking).queryByRole("button", { name: "Use a passkey" })).toBeNull();
  });

  it("keeps the generic sentence for a change the table does not name", async () => {
    answerWith({
      "POST /api/console/v1/invitations/x/revoke": STALE,
    });
    mount(<StepUpHost />);
    const { client } = await import("../api/client.gen");
    void client.post({ url: "/api/console/v1/invitations/x/revoke", body: {}, throwOnError: false });
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("This change needs a recent second factor.");
  });
});

describe("a passkey in the step-up (SU11, SU14)", () => {
  const OPTIONS = "/api/console/v1/session/verify/passkey/options";
  const PASSKEY = "/api/console/v1/session/verify/passkey";
  const bytes = (value: number[]) => new Uint8Array(value).buffer;
  const credential = {
    id: "AQID",
    rawId: bytes([1, 2, 3]),
    type: "public-key",
    response: { clientDataJSON: bytes([4]), authenticatorData: bytes([5]), signature: bytes([6]), userHandle: null },
  };

  const SETTINGS = "GET /api/console/v1/settings";
  const security = (passkeys: number) => ({
    body: { security: { authenticator: true, passkeys, recovery_remaining: 10, requirement: "optional", available: true } },
  });

  function passkeyWorkspace(finish: (count: number) => { status?: number; body: unknown }) {
    let verified = false;
    let challenges = 0;
    let finishes = 0;
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      [SETTINGS]: security(1),
      [`POST ${INVITE}`]: () => (verified ? { body: { invitation_id: "x", expires_at: "2030-01-01T00:00:00Z" } } : STALE),
      [`POST ${OPTIONS}`]: () => {
        challenges += 1;
        const challenge = btoa(`challenge${String(challenges)}`).replace(/=+$/, "");
        return { body: { options: { challenge, allowCredentials: [{ id: "AQID", type: "public-key" }], userVerification: "required" } } };
      },
      [`POST ${PASSKEY}`]: () => {
        finishes += 1;
        const reply = finish(finishes);
        if (reply.status === undefined) verified = true;
        return reply;
      },
    });
    return calls;
  }

  function browser(get: (options: CredentialRequestOptions) => Promise<unknown>) {
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {
      return undefined;
    });
    const spy = vi.fn(get);
    Object.defineProperty(navigator, "credentials", { configurable: true, value: { get: spy } });
    return spy;
  }

  const challengeOf = (call: unknown[] | undefined) => {
    const options = call?.[0] as { publicKey: { challenge: Uint8Array } } | undefined;
    return options === undefined ? "" : new TextDecoder().decode(options.publicKey.challenge);
  };

  it("asks the browser inside the click, sends the assertion and finishes the change", async () => {
    const calls = passkeyWorkspace(() => ({ body: { csrf_token: "rotated-token" } }));
    const get = browser(() => Promise.resolve(credential));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    const button = await within(asking).findByRole("button", { name: "Use a passkey" });
    expect(asking).toHaveTextContent("or use a passkey.");
    // The code field keeps the focus; nothing focuses the passkey button.
    await waitFor(() => { expect(within(asking).getByLabelText("Authentication code")).toHaveFocus(); });
    fireEvent.click(button);
    // Called synchronously in the click, before anything was awaited.
    expect(get).toHaveBeenCalledTimes(1);
    expect(challengeOf(get.mock.calls[0])).toBe("challenge1");
    expect(await screen.findByText(/Invitation queued\./)).toBeInTheDocument();
    const sent = calls.find((call) => call.path === PASSKEY);
    expect(sent?.body).toEqual({
      credential: {
        id: "AQID",
        rawId: "AQID",
        type: "public-key",
        response: { clientDataJSON: "BA", authenticatorData: "BQ", signature: "Bg" },
      },
    });
    const invitations = calls.filter((call) => call.path === INVITE && call.method === "POST");
    expect(invitations[1]?.headers.get("X-CSRF-Token")).toBe("rotated-token");
  });

  it("spends the options on every attempt and uses fresh ones for the next click", async () => {
    const calls = passkeyWorkspace((count) =>
      count === 1 ? { status: 400, body: { code: "INVALID_FACTOR", detail: "x" } } : { body: { csrf_token: "rotated-token" } },
    );
    const get = browser(() => Promise.resolve(credential));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    fireEvent.click(await within(asking).findByRole("button", { name: "Use a passkey" }));
    expect(await within(asking).findByRole("alert")).toHaveTextContent("That passkey could not be used.");
    await waitFor(() => { expect(calls.filter((call) => call.path === OPTIONS)).toHaveLength(2); });
    await settle();
    fireEvent.click(within(asking).getByRole("button", { name: "Use a passkey" }));
    expect(get).toHaveBeenCalledTimes(2);
    expect(challengeOf(get.mock.calls[1])).toBe("challenge2");
    expect(await screen.findByText(/Invitation queued\./)).toBeInTheDocument();
  });

  it("keeps unspent options when the prompt is cancelled", async () => {
    const calls = passkeyWorkspace(() => ({ body: { csrf_token: "rotated-token" } }));
    const get = browser(() => Promise.reject(new DOMException("cancelled", "NotAllowedError")));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    fireEvent.click(await within(asking).findByRole("button", { name: "Use a passkey" }));
    expect(await within(asking).findByRole("alert")).toHaveTextContent(
      "The passkey prompt was cancelled or did not finish. Try again, or enter a code.",
    );
    fireEvent.click(within(asking).getByRole("button", { name: "Use a passkey" }));
    expect(get).toHaveBeenCalledTimes(2);
    expect(challengeOf(get.mock.calls[1])).toBe("challenge1");
    expect(calls.filter((call) => call.path === OPTIONS)).toHaveLength(1);
    expect(calls.filter((call) => call.path === PASSKEY)).toHaveLength(0);
  });

  it("fetches fresh options instead of asking with stale ones, and says to choose again", async () => {
    const calls = passkeyWorkspace(() => ({ body: { csrf_token: "rotated-token" } }));
    const get = browser(() => Promise.resolve(credential));
    const now = vi.spyOn(Date, "now");
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    const button = await within(asking).findByRole("button", { name: "Use a passkey" });
    const opened = Date.now();
    now.mockReturnValue(opened + 5 * 60 * 1000);
    fireEvent.click(button);
    expect(get).not.toHaveBeenCalled();
    expect(within(asking).getByRole("status")).toHaveTextContent("Choose Use a passkey again to continue.");
    await waitFor(() => { expect(calls.filter((call) => call.path === OPTIONS)).toHaveLength(2); });
    await settle();
    fireEvent.click(button);
    expect(get).toHaveBeenCalledTimes(1);
    expect(challengeOf(get.mock.calls[0])).toBe("challenge2");
    now.mockRestore();
  });

  it("asks for no options where the account has no passkey saved", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      [SETTINGS]: security(0),
      [`POST ${INVITE}`]: STALE,
    });
    browser(() => Promise.resolve(credential));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await settle();
    expect(calls.some((call) => call.path === "/api/console/v1/settings")).toBe(true);
    expect(calls.some((call) => call.path === OPTIONS)).toBe(false);
    expect(within(asking).queryByRole("button", { name: "Use a passkey" })).toBeNull();
    expect(asking).not.toHaveTextContent("or use a passkey");
  });

  it("falls back to the options' answer where My account cannot be read", async () => {
    const calls = answerWith({
      "GET /api/console/v1/access": { body: ACCESS },
      [SETTINGS]: { status: 503, body: { code: "UNAVAILABLE", detail: "x" } },
      [`POST ${INVITE}`]: STALE,
      [`POST ${OPTIONS}`]: { status: 409, body: { code: "CONFLICT", detail: "x" } },
    });
    browser(() => Promise.resolve(credential));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await waitFor(() => { expect(calls.some((call) => call.path === OPTIONS)).toBe(true); });
    await settle();
    expect(within(asking).queryByRole("button", { name: "Use a passkey" })).toBeNull();
  });

  it("offers no passkey where the browser cannot ask for one", async () => {
    const calls = passkeyWorkspace(() => ({ body: { csrf_token: "rotated-token" } }));
    mount(<InviteTeammate />);
    await invite();
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    await settle();
    expect(calls.some((call) => call.path === OPTIONS)).toBe(false);
    expect(within(asking).queryByRole("button", { name: "Use a passkey" })).toBeNull();
  });
});
