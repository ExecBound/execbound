// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readAccountQueryKey } from "../../api/@tanstack/react-query.gen";
import type { AccountView } from "../../api/types.gen";
import { answerWith, heldReply, type Reply, renderPage, settle, UNAVAILABLE } from "../../test/page";
import { SecurityChanges } from "./SecurityNotifications";

const ACCOUNT = "/api/console/v1/account";
const LOADED: AccountView = {
  name: "Dana",
  requests: [],
  notifications: [{ sequence: 7, at: "2026-10-06T09:00:00Z", message: "A second factor was added." }],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the sign-in security log", () => {
  it("keeps the notifications it read through a poll that fails", async () => {
    let reads = 0;
    answerWith({ [`GET ${ACCOUNT}`]: () => (++reads === 1 ? { body: LOADED } : UNAVAILABLE) });
    const { queryClient } = renderPage(<SecurityChanges />);
    expect(await screen.findByText("A second factor was added.")).toBeInTheDocument();
    // The drawer's 30-second poll, here failing.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: readAccountQueryKey() });
    });
    expect(reads).toBe(2);
    expect(await screen.findByText(/Notifications could not be loaded/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByText("A second factor was added.")).toBeInTheDocument();
  });

  it("keeps Try again, and the focus on it, while the notifications are read again", async () => {
    const out = heldReply();
    const replies: Promise<Reply>[] = [Promise.resolve(UNAVAILABLE), out.reply];
    let reads = 0;
    answerWith({ [`GET ${ACCOUNT}`]: () => replies[reads++] ?? UNAVAILABLE });
    renderPage(<SecurityChanges />);
    const button = await screen.findByRole("button", { name: "Try again" });
    const user = userEvent.setup();
    await user.click(button);
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    await settle();
    expect(button).toBeInTheDocument();
    expect(button).toHaveFocus();
    expect(button).toHaveAttribute("aria-disabled", "true");
    out.send(UNAVAILABLE);
    await waitFor(() => {
      expect(button).not.toHaveAttribute("aria-disabled");
    });
    expect(button).toHaveFocus();
  });
});
