// SPDX-License-Identifier: AGPL-3.0-only
// Add a reporting source (MC14, MC17, #678): the lifetimes offered with 30 days the default,
// the three heartbeat intervals, the intake-only sentence above the button, and the token
// shown once through the show-once path; a refusal for a stale factor asks for a code naming the
// change, and the token is nowhere once its dialog closes.

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readMonitorQueryKey } from "../../api/@tanstack/react-query.gen";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, heldReply, keptNowhere, renderPage, settle, type Seen } from "../../test/page";
import { minted, options, SPACE_A, SPACE_B, TOKEN } from "../../test/source-data";
import { StepUpHost } from "../StepUpHost";
import { AddSource } from "./AddSource";

const SOURCES = "/api/console/v1/monitor/sources";
const VERIFY = "/api/console/v1/session/verify";
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", space: { id: SPACE_A, name: "Customer A", archived: false }, spaces: 2 };
const IN_B: SessionSummary = { ...ADMIN, space: { id: SPACE_B, name: "Customer B", archived: false } };
const STALE = { status: 401, body: { code: "MFA_REQUIRED", detail: "Verify your identity to continue." } };
const INTAKE_ONLY =
  "This token authorizes intake only. It lets one Tines story send events about itself to ExecBound. It cannot run actions, approve requests or read anything from ExecBound.";

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

function open(storyId?: string, session: SessionSummary = ADMIN) {
  const onClose = vi.fn();
  const onMinted = vi.fn();
  const rendered = renderPage(
    <>
      <AddSource storyId={storyId} onClose={onClose} onMinted={onMinted} />
      <StepUpHost />
    </>,
    session,
  );
  return { ...rendered, onClose, onMinted };
}

describe("Add a reporting source (MC14)", () => {
  it("offers 1, 7 or 30 days with 30 the default, three heartbeats, and says the token authorizes intake only", async () => {
    answerWith({});
    open();
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    const lifetime = within(dialog).getByLabelText("Token valid for");
    expect(within(lifetime).getAllByRole("option").map((option) => option.textContent)).toEqual(["1 day", "7 days", "30 days"]);
    expect(lifetime).toHaveValue("30");
    const heartbeat = within(dialog).getByLabelText("Expected heartbeat");
    // No heartbeat every minute: the health pass would call the source silent two minutes after
    // it is added, before most stories are built.
    expect(within(heartbeat).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "Every 5 minutes",
      "Every 15 minutes",
      "Every hour",
    ]);
    expect(heartbeat).toHaveValue("300");
    expect(dialog).toHaveTextContent(INTAKE_ONLY);
    expect(dialog).toHaveTextContent("This source belongs to Customer A.");
  });

  it("refuses to send a story ID the server would refuse", async () => {
    const calls = answerWith({});
    open();
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.type(within(dialog).getByLabelText("Tines story ID"), "has space");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(await within(dialog).findByText(/A story ID is letters, digits/)).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("fills the story ID it was opened for", async () => {
    answerWith({});
    open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    expect(within(dialog).getByLabelText("Tines story ID")).toHaveValue("4001");
    expect(within(dialog).getByLabelText("Source name")).toHaveValue("Story 4001");
  });

  it("creates the source, shows the token once and keeps it nowhere afterwards", async () => {
    const calls = answerWith({ [`POST ${SOURCES}`]: { status: 201, body: minted() } });
    const { queryClient, onMinted } = open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.selectOptions(within(dialog).getByLabelText("Token valid for"), "7");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    expect(within(shown).getByLabelText(/Source token/)).toHaveValue(TOKEN);
    const posts = calls.filter((call) => call.method === "POST" && call.path === SOURCES);
    expect(posts.map((call) => call.body)).toEqual([{ label: "Story 4001", story_id: "4001", lifetime_days: 7, heartbeat_seconds: 300 }]);
    // While the token is shown it is in this dialog's state only, in no cache.
    expect(JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))).not.toContain(TOKEN);
    await userEvent.click(within(shown).getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(onMinted).toHaveBeenCalledWith(minted().source_id, "4001");
    });
    await keptNowhere(queryClient, TOKEN);
  });

  it("says why in its own words when the workspace is full", async () => {
    answerWith({ [`POST ${SOURCES}`]: { status: 409, body: { code: "SOURCE_CAPACITY", detail: "x" } } });
    const { onMinted } = open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    // Revoked sources count toward the limit and are kept, so revoking one makes no room.
    expect(
      await within(dialog).findByText(
        "This workspace has as many reporting sources as it can hold: 100, revoked ones included, so revoking one does not make room.",
      ),
    ).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent(/Revoke one/);
    expect(onMinted).not.toHaveBeenCalled();
  });

  it("says a story already has a source to rotate, and never to revoke it first", async () => {
    answerWith({ [`POST ${SOURCES}`]: { status: 409, body: { code: "SOURCE_EXISTS", detail: "x" } } });
    open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    // A source that has kept all its events never refuses its story's next one, so the source
    // this refusal finds still takes events, and rotating it is the way to a new token.
    expect(
      await within(dialog).findByText("This Space already has a reporting source for that story. Rotate its token on Connections to issue a new one."),
    ).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent(/revoke/i);
  });

  it("never says nothing was changed when the answer did not arrive, and reads the sources again", async () => {
    answerWith({ [`POST ${SOURCES}`]: { status: 503, body: { code: "UNAVAILABLE", detail: "x" } } });
    const { queryClient } = open("4001");
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(
      await within(dialog).findByText(
        "ExecBound did not confirm the source, so it may have been created. Look for it on Connections before trying again; a Space holds one source for a story that can still take its events, so trying again cannot add another.",
      ),
    ).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent(/nothing was changed/);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: readMonitorQueryKey() });
  });

  it("adds nothing in a Space this administrator only reviews, and says so before any code is asked", async () => {
    const calls = answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: false } }),
      },
    });
    open("4001", IN_B);
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await settle();
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(
      await within(dialog).findByText(
        "You review Customer B but do not administer it, so a reporting source cannot be added there. Choose a Space you administer.",
      ),
    ).toBeInTheDocument();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("names the one Space an administrator narrowed to it writes in, not the workspace's default", async () => {
    answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }),
      },
    });
    open("4001", { ...ADMIN, space: null, spaces: 1 });
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await within(dialog).findByText(/This source belongs to Customer B\./);
    expect(dialog).not.toHaveTextContent(/default Space/);
  });

  it("adds nothing in that one Space once it is archived, and asks for no other it cannot choose", async () => {
    const calls = answerWith({
      "GET /api/console/v1/monitor/connect": {
        body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: true, administered: true } }),
      },
    });
    open("4001", { ...ADMIN, space: null, spaces: 1 });
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await within(dialog).findByText(/This source belongs to Customer B\./);
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Customer B is archived and takes no new source.");
    expect(within(dialog).getByRole("alert")).not.toHaveTextContent(/Choose an active Space/);
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("reads where it lands again once the session has moved to another Space, and adds nothing until it has", async () => {
    const held = heldReply();
    let reads = 0;
    const calls = answerWith({
      // The first answer was read while the session was in Customer B, before another tab moved
      // it to Customer A, where the server now writes.
      "GET /api/console/v1/monitor/connect": () => {
        reads += 1;
        return reads === 1
          ? { body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }) }
          : held.reply;
      },
    });
    open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    expect(dialog).not.toHaveTextContent(/belongs to Customer B/);
    expect(dialog).toHaveTextContent("Checking which Space this lands in…");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    held.send({ body: options() });
    await within(dialog).findByText(/This source belongs to Customer A\./);
  });

  it("follows the session from Space to Space while the form is open, reading again each time they disagree", async () => {
    // Where the server writes now, which another tab moves; the session this tab reads follows.
    let server = { space_id: SPACE_A, name: "Customer A", archived: false, administered: true };
    const B = { space_id: SPACE_B, name: "Customer B", archived: false, administered: true };
    const A = server;
    const calls = answerWith({ "GET /api/console/v1/monitor/connect": () => ({ body: options({ placement: server }) }) });
    let move: (space: typeof A) => void = () => undefined;
    function Moving() {
      const [space, setSpace] = useState(A);
      move = setSpace;
      return (
        <SessionContext.Provider value={{ ...ADMIN, space: { id: space.space_id, name: space.name, archived: false } }}>
          <AddSource storyId="4001" onClose={vi.fn()} />
        </SessionContext.Provider>
      );
    }
    renderPage(<Moving />, ADMIN);
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await within(dialog).findByText(/This source belongs to Customer A\./);
    const reads = () => calls.filter((call) => call.path === "/api/console/v1/monitor/connect").length;
    expect(reads()).toBe(1);
    // The session this tab read names Customer B before the server does: its newer word stands.
    act(() => {
      move(B);
    });
    await waitFor(() => {
      expect(reads()).toBe(2);
    });
    await within(dialog).findByText(/This source belongs to Customer A\./);
    act(() => {
      move(A);
    });
    await settle();
    // The same disagreement again, once the server has moved too, is read again rather than left.
    server = B;
    act(() => {
      move(B);
    });
    await within(dialog).findByText(/This source belongs to Customer B\./);
    expect(reads()).toBe(3);
  });

  it("reads where it lands once when the session's Space agrees with it", async () => {
    const calls = answerWith({ "GET /api/console/v1/monitor/connect": { body: options() } });
    open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await within(dialog).findByText(/This source belongs to Customer A\./);
    await settle();
    expect(calls.filter((call) => call.path === "/api/console/v1/monitor/connect")).toHaveLength(1);
  });

  it("says why when the server finds the Space is not this administrator's", async () => {
    answerWith({ [`POST ${SOURCES}`]: { status: 403, body: { code: "FORBIDDEN", detail: "x" } } });
    open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    expect(
      await within(dialog).findByText(
        "This Space is one you review, not one you administer, so its reporting sources are not yours to change.",
      ),
    ).toBeInTheDocument();
  });

  it("asks for a code once, naming the change, and sends it again", async () => {
    let verified = false;
    const calls = answerWith({
      [`POST ${SOURCES}`]: () => (verified ? { status: 201, body: minted() } : STALE),
      [`POST ${VERIFY}`]: (seen: Seen) => {
        verified = (seen.body as { code: string }).code === "123456";
        return verified ? { body: { csrf_token: "rotated-token" } } : { status: 400, body: { code: "INVALID_FACTOR", detail: "x" } };
      },
    });
    const { queryClient } = open("4001");
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Create source" }));
    const asking = await screen.findByRole("dialog", { name: "Verify your identity" });
    expect(asking).toHaveTextContent("To create a reporting source, confirm it is you.");
    await userEvent.type(within(asking).getByLabelText("Authentication code"), "123456");
    await userEvent.click(within(asking).getByRole("button", { name: "Verify" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    expect(within(shown).getByLabelText(/Source token/)).toHaveValue(TOKEN);
    expect(calls.filter((call) => call.method === "POST" && call.path === SOURCES)).toHaveLength(2);
    await userEvent.click(within(shown).getByRole("button", { name: "I have copied it" }));
    await keptNowhere(queryClient, TOKEN);
  });
});
