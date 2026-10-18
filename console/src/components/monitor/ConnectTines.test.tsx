// SPDX-License-Identifier: AGPL-3.0-only
// Connect Tines (MC2, MC17, #678): the form refuses to send until every field is one the server
// would take; the key is a password field kept in component state alone, and after success,
// failure or close it is in no query or mutation record, no browser storage and nowhere in the
// document. A refusal for a stale factor asks for a code once, naming the change, and sends the
// change again.

import type { QueryClient } from "@tanstack/react-query";
import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { connection } from "../../test/monitor-data";
import { answerWith, heldReply, keptNowhere, renderPage, type Seen } from "../../test/page";
import { options, SPACE_A, SPACE_B } from "../../test/source-data";
import { StepUpHost } from "../StepUpHost";
import { ConnectTines } from "./ConnectTines";

const SENTINEL = "SENTINEL-pasted-tines-key-3e91";
const TINES = "/api/console/v1/monitor/connections/tines";
const VERIFY = "/api/console/v1/session/verify";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", space: { id: SPACE_A, name: "Customer A", archived: false }, spaces: 2 };
const CREATED = connection({ connection_id: "cccccccc-0000-4000-8000-000000000009", credential_mode: "sealed", label: "Tines" });
const STALE = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

function open(session: SessionSummary = ADMIN) {
  const onClose = vi.fn();
  const onConnected = vi.fn();
  const rendered = renderPage(
    <>
      <ConnectTines onClose={onClose} onConnected={onConnected} />
      <StepUpHost />
    </>,
    session,
  );
  return { ...rendered, onClose, onConnected };
}

async function fill(dialog: HTMLElement, key = SENTINEL) {
  await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  await userEvent.type(within(dialog).getByLabelText("Tines tenant URL"), "https://acme.tines.com");
  await userEvent.type(within(dialog).getByLabelText("API key"), key);
}

/** Nothing the console keeps holds the key: the query and mutation records, browser storage
 * and the document. */
async function nowhere(queryClient: QueryClient) {
  await keptNowhere(queryClient, SENTINEL);
}

describe("Connect Tines (MC2)", () => {
  it("says what ExecBound reads first, then refuses to send until each field is one the server takes", async () => {
    const calls = answerWith({});
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    expect(dialog).toHaveTextContent("Monitoring is visibility. It does not enforce action policy or prevent a Tines action from running.");
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    const connect = within(dialog).getByRole("button", { name: "Connect" });
    expect(connect).toBeDisabled();
    const key = within(dialog).getByLabelText("API key");
    expect(key).toHaveAttribute("type", "password");
    expect(key).toHaveAttribute("autocomplete", "off");
    await userEvent.type(within(dialog).getByLabelText("Tines tenant URL"), "https://acme.example.com");
    await userEvent.type(key, SENTINEL);
    expect(connect).toBeDisabled();
    expect(within(dialog).getByText(/Use your Tines tenant's address/)).toBeInTheDocument();
    await userEvent.clear(within(dialog).getByLabelText("Tines tenant URL"));
    await userEvent.type(within(dialog).getByLabelText("Tines tenant URL"), "https://acme.tines.com");
    await userEvent.type(within(dialog).getByLabelText("Team ID (optional)"), "has space");
    expect(connect).toBeDisabled();
    await userEvent.clear(within(dialog).getByLabelText("Team ID (optional)"));
    expect(connect).toBeEnabled();
    expect(dialog).toHaveTextContent("This connection belongs to Customer A.");
    expect(dialog).toHaveTextContent(
      "When you connect, the key is sealed for ExecBound's collector. This web service cannot read it back, and it is never shown again.",
    );
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("sends the key once, opens verification for the new connection and keeps the key nowhere", async () => {
    const calls = answerWith({ [`POST ${TINES}`]: { status: 201, body: CREATED } });
    const { queryClient, onConnected } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await userEvent.click(within(dialog).getByRole("button", { name: "Connect" }));
    await waitFor(() => {
      expect(onConnected).toHaveBeenCalledWith(CREATED.connection_id);
    });
    const posts = calls.filter((call) => call.method === "POST" && call.path === TINES);
    expect(posts.map((call) => call.body)).toEqual([{ label: "Tines", base_url: "https://acme.tines.com", api_key: SENTINEL }]);
    await nowhere(queryClient);
  });

  it("clears the key after a refusal and says why in its own words", async () => {
    answerWith({ [`POST ${TINES}`]: { status: 409, body: { code: "CONNECTION_EXISTS", detail: "x" } } });
    const { queryClient, onConnected } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await userEvent.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(await within(dialog).findByText(/already has an active connection for that platform/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("API key")).toHaveValue("");
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeDisabled();
    expect(onConnected).not.toHaveBeenCalled();
    await nowhere(queryClient);
  });

  it("keeps the key nowhere once the dialog closes unsent", async () => {
    const calls = answerWith({});
    const { queryClient, onClose } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await userEvent.click(within(dialog).getByRole("button", { name: "Close" }));
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    await nowhere(queryClient);
  });

  it("asks for a code once, naming Connect Tines, and sends the change again", async () => {
    let verified = false;
    const calls = answerWith({
      [`POST ${TINES}`]: () => (verified ? { status: 201, body: CREATED } : STALE),
      [`POST ${VERIFY}`]: (seen: Seen) => {
        verified = (seen.body as { code: string }).code === "123456";
        return verified ? { body: { csrf_token: "rotated-token" } } : { status: 400, body: { code: "INVALID_FACTOR", detail: "x" } };
      },
    });
    const { queryClient, onConnected } = open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await userEvent.click(within(dialog).getByRole("button", { name: "Connect" }));
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("To connect Tines, confirm it is you.");
    expect(asking).not.toHaveTextContent(SENTINEL);
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    await waitFor(() => {
      expect(onConnected).toHaveBeenCalledWith(CREATED.connection_id);
    });
    const posts = calls.filter((call) => call.method === "POST" && call.path === TINES);
    expect(posts).toHaveLength(2);
    expect(posts[1]?.body).toEqual(posts[0]?.body);
    expect(calls.filter((call) => call.path === VERIFY)).toHaveLength(1);
    await nowhere(queryClient);
  });

  it("names the one Space an administrator narrowed to it writes in, not the workspace's default", async () => {
    answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: { ...options(), placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } },
      },
    });
    open({ ...ADMIN, space: null, spaces: 1 });
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    await within(dialog).findByText(/This connection belongs to Customer B\./);
    expect(dialog).not.toHaveTextContent(/default Space/);
  });

  it("connects nothing until it has read where the connection lands, once the session has moved to another Space", async () => {
    const held = heldReply();
    let reads = 0;
    const calls = answerWith({
      // Read while the session was in Customer B; another tab has since moved it to Customer A.
      "GET /api/console/v1/monitor/connect": () => {
        reads += 1;
        return reads === 1
          ? { body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }) }
          : held.reply;
      },
    });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    expect(dialog).not.toHaveTextContent(/belongs to Customer B/);
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeDisabled();
    held.send({ body: options() });
    await within(dialog).findByText(/This connection belongs to Customer A\./);
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeEnabled();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("adds no connection in a Space this administrator only reviews, and says so on its first step, before it asks for the key", async () => {
    const calls = answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: options({ placement: { space_id: SPACE_A, name: "Customer A", archived: false, administered: false } }),
      },
    });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    expect(
      await within(dialog).findByText(
        "You review Customer A but do not administer it, so a connection cannot be added there. Choose a Space you administer.",
      ),
    ).toBeInTheDocument();
    expect(dialog).toHaveTextContent("Step 1 of 2");
    expect(within(dialog).queryByLabelText("API key")).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("says why when the server finds the Space is not this administrator's", async () => {
    answerWith({ [`POST ${TINES}`]: { status: 403, body: { code: "FORBIDDEN", detail: "x" } } });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    await userEvent.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(
      await within(dialog).findByText(
        "This Space is one you review, not one you administer, so its monitoring connections are not yours to change.",
      ),
    ).toBeInTheDocument();
  });

  it("does not place a connection where no Space is chosen, or in an archived one, and says so before it asks for the key", async () => {
    answerWith({});
    open({ ...ADMIN, space: null });
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    expect(within(dialog).getByRole("alert")).toHaveTextContent("choose a Space");
    expect(within(dialog).queryByLabelText("API key")).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Continue" })).toBeDisabled();
    cleanup();
    open({ ...ADMIN, space: { id: "aaaaaaaa-0000-4000-8000-000000000002", name: "Customer A", archived: true } });
    const archived = await screen.findByRole("dialog", { name: "Connect Tines" });
    // With no placement read, the form names the session's Space as the one it would land in.
    expect(within(archived).getByRole("alert")).toHaveTextContent(
      "Customer A is archived and takes no new connection. Choose an active Space first.",
    );
    expect(within(archived).queryByLabelText("API key")).toBeNull();
    expect(within(archived).getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("says so where the key is asked when the Space it lands in turns out to be one this administrator only reviews", async () => {
    const held = heldReply();
    let reads = 0;
    const calls = answerWith({
      // Read while the session was in Customer B; another tab has since moved it to Customer A,
      // which this administrator only reviews.
      "GET /api/console/v1/monitor/connect": () => {
        reads += 1;
        return reads === 1
          ? { body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }) }
          : held.reply;
      },
    });
    open();
    const dialog = await screen.findByRole("dialog", { name: "Connect Tines" });
    await fill(dialog);
    held.send({ body: options({ placement: { space_id: SPACE_A, name: "Customer A", archived: false, administered: false } }) });
    expect(
      await within(dialog).findByText(
        "You review Customer A but do not administer it, so a connection cannot be added there. Choose a Space you administer.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Connect" })).toBeDisabled();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });
});
