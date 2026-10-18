// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readAccountQueryKey } from "../../api/@tanstack/react-query.gen";
import type { AccountView, PersonalSettingsView } from "../../api/types.gen";
import { answerWith, heldReply, type Reply, renderPage, settle, UNAVAILABLE } from "../../test/page";
import { AccountDetails } from "./AccountDetails";

const ACCOUNT = "/api/console/v1/account";
const LOADED: AccountView = { name: "Dana", requests: [], notifications: [] };
const IDENTITY: PersonalSettingsView = {
  identity: { principal_id: "6d2c1f0a-0000-4000-8000-000000000001", kind: "HUMAN_APPROVER", credential_id: "c0ffee00-0000-4000-8000-000000000002" },
  tenant_name: "Synthetic SOC",
  email: "dana@example.com",
  has_password: true,
  credential: { issued_at: "2026-09-19T04:00:00+00:00", expires_at: "2026-09-19T12:00:00+00:00" },
  sessions: [],
  others: 0,
  directory: { provider: null, link: null },
  weekly_summary: { available: false, subscribed: false, address: null },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the profile and requests on My account", () => {
  it("keeps the profile, and a name being typed into it, through a read that fails", async () => {
    let reads = 0;
    answerWith({ [`GET ${ACCOUNT}`]: () => (++reads === 1 ? { body: LOADED } : UNAVAILABLE) });
    const { queryClient } = renderPage(<AccountDetails identity={IDENTITY} />);
    const field = await screen.findByLabelText("Display name");
    const user = userEvent.setup();
    await user.clear(field);
    await user.type(field, "Dana R");
    // What returning to the tab, or the bell's poll, does to the account: it reads it again,
    // and here that read fails.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: readAccountQueryKey() });
    });
    expect(reads).toBe(2);
    // The failure is said beside the profile, with its Try again, rather than in its place.
    expect(await screen.findByText(/Your profile could not be loaded/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByLabelText("Display name")).toBe(field);
    expect(field).toHaveValue("Dana R");
    expect(screen.getByRole("heading", { name: "Your data and account" })).toBeInTheDocument();
  });

  it("keeps Try again, and the focus on it, while the profile is read again", async () => {
    const replies: Promise<Reply>[] = [];
    const first = heldReply();
    const second = heldReply();
    replies.push(Promise.resolve(UNAVAILABLE), first.reply, second.reply);
    let reads = 0;
    answerWith({ [`GET ${ACCOUNT}`]: () => replies[reads++] ?? UNAVAILABLE });
    renderPage(<AccountDetails identity={IDENTITY} />);
    const button = await screen.findByRole("button", { name: "Try again" });
    const user = userEvent.setup();
    await user.click(button);
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    await settle();
    // The read is out again: the button is where it was, marked unavailable, and has the focus.
    expect(button).toBeInTheDocument();
    expect(button).toHaveFocus();
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(screen.queryByText("Loading your profile…")).toBeNull();
    // Pressing it while the read is out asks for nothing more.
    await user.click(button);
    await settle();
    expect(reads).toBe(2);

    first.send(UNAVAILABLE);
    await waitFor(() => {
      expect(button).not.toHaveAttribute("aria-disabled");
    });
    expect(button).toHaveFocus();
    expect(screen.getByText(/Your profile could not be loaded/)).toBeInTheDocument();

    await user.click(button);
    second.send({ body: LOADED });
    expect(await screen.findByLabelText("Display name")).toHaveValue("Dana");
    expect(screen.queryByText(/Your profile could not be loaded/)).toBeNull();
    expect(reads).toBe(3);
  });
});
