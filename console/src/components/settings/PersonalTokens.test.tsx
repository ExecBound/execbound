// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listOwnTokensQueryKey } from "../../api/@tanstack/react-query.gen";
import type { TokenRow } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, heldReply, type Reply, renderPage, type Seen, settle, UNAVAILABLE } from "../../test/page";
import { WorkspaceTokens } from "../tenant/WorkspaceTokens";
import { PersonalTokens } from "./PersonalTokens";

const TOKENS = "/api/console/v1/settings/tokens";
const WORKSPACE = "/api/console/v1/tenant/tokens";
const SECRET = "ebp1.4b2c7a1e-0000-4000-8000-000000000009.4b2c7a1e-0000-4000-8000-000000000003.secret-under-test";

const row: TokenRow = {
  token_id: "4b2c7a1e-0000-4000-8000-000000000001",
  credential_id: "4b2c7a1e-0000-4000-8000-000000000021",
  name: "Coding agent on my laptop",
  owner_id: "4b2c7a1e-0000-4000-8000-000000000002",
  owner_label: "Admin",
  created_at: "2026-09-25T12:00:00Z",
  expires_at: "2026-10-25T12:00:00Z",
  last_used_at: null,
  state: "live",
};
const created: TokenRow = { ...row, token_id: "4b2c7a1e-0000-4000-8000-000000000003", name: "CI" };
const expired: TokenRow = {
  ...row,
  token_id: "4b2c7a1e-0000-4000-8000-000000000004",
  name: "Old CI",
  expires_at: "2026-09-01T12:00:00Z",
  state: "expired",
};
// Revoked through its backing credential (a deactivation, a password reset or a promotion):
// the list says revoked, whichever of the two it was.
const underneath: TokenRow = {
  ...row,
  token_id: "4b2c7a1e-0000-4000-8000-000000000005",
  name: "Laptop before the reset",
  state: "revoked",
};

function gets(seen: Seen[], path: string): number {
  return seen.filter((request) => request.method === "GET" && request.path === path).length;
}

function posts(seen: Seen[]): Seen[] {
  return seen.filter((request) => request.method === "POST");
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

describe("PersonalTokens", () => {
  it("creates a token from the name and lifetime asked for, shows it once, and then it is nowhere", async () => {
    let listed = [row];
    const seen = answerWith({
      [`GET ${TOKENS}`]: () => ({ body: { tokens: listed } }),
      [`POST ${TOKENS}/issue`]: () => {
        listed = [created, row];
        return { body: { token: SECRET, row: created } };
      },
    });
    const { queryClient } = renderPage(<PersonalTokens />);
    expect(await screen.findByText("Coding agent on my laptop")).toBeInTheDocument();
    expect(screen.getByText("Never used")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Create token" }));
    const form = await screen.findByRole("dialog", { name: "Create a personal access token" });
    await user.type(within(form).getByLabelText("Name"), "CI");
    await user.click(within(form).getByRole("button", { name: "Create" }));

    const shown = await screen.findByRole("dialog", { name: "Copy the token now" });
    expect(within(shown).getByLabelText("Token (copy it now)")).toHaveValue(SECRET);
    expect(shown).toHaveTextContent("The token CI is shown once.");
    expect(shown).toHaveTextContent("Authorization: Bearer <token>");
    expect(shown).toHaveTextContent("It expires 2026-10-25 12:00 UTC.");
    expect(shown).not.toHaveTextContent(/credential/i);
    expect(shown).not.toHaveTextContent("administrator 4b2c7a1e");
    const issued = posts(seen);
    expect(issued).toHaveLength(1);
    expect(issued[0]?.path).toBe(`${TOKENS}/issue`);
    expect(issued[0]?.headers.get("x-csrf-token")).toBe("token-under-test");
    expect(issued[0]?.body).toEqual({ name: "CI", lifetime: "720" });

    await user.click(within(shown).getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    // The list is read again after the create, and shows the new token.
    expect(await screen.findByRole("cell", { name: "CI" })).toBeInTheDocument();
    expect(gets(seen, TOKENS)).toBe(2);
    expect(document.body.innerHTML).not.toContain(SECRET);
    await waitFor(() => {
      expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
    });
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state))).not.toContain(SECRET);
  });

  it("explains a refused create in a token's words and forgets it when the dialog opens again", async () => {
    answerWith({
      [`GET ${TOKENS}`]: { body: { tokens: [] } },
      [`POST ${TOKENS}/issue`]: { status: 403, body: { code: "DIRECTORY_REQUIRED", detail: "<b>server text</b>" } },
    });
    renderPage(<PersonalTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a personal access token" });
    await user.type(within(dialog).getByLabelText("Name"), "CI");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "This workspace requires organization sign-in, so it does not accept personal access tokens.",
    );
    expect(screen.queryByText(/server text/)).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    await user.click(screen.getByRole("button", { name: "Create token" }));
    const again = await screen.findByRole("dialog", { name: "Create a personal access token" });
    expect(within(again).queryByRole("alert")).toBeNull();
  });

  it("revokes a token after confirmation and reads the workspace list again", async () => {
    let state: TokenRow["state"] = "live";
    const seen = answerWith({
      [`GET ${TOKENS}`]: () => ({ body: { tokens: [{ ...row, state }] } }),
      [`GET ${WORKSPACE}`]: () => ({ body: { tokens: [{ ...row, state }] } }),
      [`POST ${TOKENS}/${row.token_id}/revoke`]: () => {
        state = "revoked";
        return { body: { tokens: [{ ...row, state }] } };
      },
    });
    renderPage(
      <>
        <PersonalTokens />
        <WorkspaceTokens />
      </>,
    );
    const user = userEvent.setup();
    const mine = await screen.findByRole("table", { name: "Your personal access tokens." });
    await user.click(within(mine).getByRole("button", { name: "Revoke Coding agent on my laptop" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke Coding agent on my laptop?" });
    expect(posts(seen)).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await screen.findByText("Token revoked.")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    const posted = posts(seen);
    expect(posted.map((request) => request.path)).toEqual([`${TOKENS}/${row.token_id}/revoke`]);
    expect(posted[0]?.body).toEqual({});
    // The answer is this card's fresh list, so only the other card's list is read again.
    await waitFor(() => {
      expect(gets(seen, WORKSPACE)).toBe(2);
    });
    expect(gets(seen, TOKENS)).toBe(1);
    expect(within(mine).getByText("revoked")).toBeInTheDocument();
    expect(within(mine).getByRole("button", { name: "Delete Coding agent on my laptop" })).toBeInTheDocument();
  });

  it("explains a failed revoke and reads the list again", async () => {
    const seen = answerWith({
      [`GET ${TOKENS}`]: { body: { tokens: [row] } },
      [`POST ${TOKENS}/${row.token_id}/revoke`]: {
        status: 409,
        body: { code: "CONFLICT", detail: "<script>server text</script>" },
      },
    });
    renderPage(<PersonalTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Revoke Coding agent on my laptop" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke Coding agent on my laptop?" });
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Something changed first; the page shows what is there now.",
    );
    expect(screen.queryByText(/server text/)).toBeNull();
    await waitFor(() => {
      expect(gets(seen, TOKENS)).toBe(2);
    });
  });

  it("deletes an expired token and one revoked through its credential, each only after confirmation", async () => {
    let listed = [expired, underneath];
    const seen = answerWith({
      [`GET ${TOKENS}`]: () => ({ body: { tokens: listed } }),
      [`POST ${TOKENS}/${expired.token_id}/delete`]: () => {
        listed = [underneath];
        return { body: { tokens: listed } };
      },
      [`POST ${TOKENS}/${underneath.token_id}/delete`]: () => {
        listed = [];
        return { body: { tokens: listed } };
      },
    });
    renderPage(<PersonalTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Delete Old CI" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete Old CI?" });
    expect(dialog).toHaveTextContent("It disappears from every list. The audit history keeps it.");
    expect(posts(seen)).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Token deleted.")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(screen.queryByRole("cell", { name: "Old CI" })).toBeNull();
    // The row and the button that opened the dialog are gone: the focus goes to the table.
    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByRole("region", { name: "Your personal access tokens." }));
    });

    await user.click(screen.getByRole("button", { name: "Delete Laptop before the reset" }));
    const second = await screen.findByRole("dialog", { name: "Delete Laptop before the reset?" });
    expect(within(second).queryByRole("alert")).toBeNull();
    await user.click(within(second).getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("No tokens yet.")).toBeInTheDocument();
    // With no table left, the focus goes to the one control that remains.
    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByRole("button", { name: "Create token" }));
    });
    const posted = posts(seen);
    expect(posted.map((request) => request.path)).toEqual([
      `${TOKENS}/${expired.token_id}/delete`,
      `${TOKENS}/${underneath.token_id}/delete`,
    ]);
    expect(posted.map((request) => request.body)).toEqual([{}, {}]);
  });

  it("explains a failed delete in the dialog and reads the list again", async () => {
    const seen = answerWith({
      [`GET ${TOKENS}`]: { body: { tokens: [expired] } },
      [`POST ${TOKENS}/${expired.token_id}/delete`]: { status: 409, body: { code: "CONFLICT", detail: "x" } },
    });
    renderPage(<PersonalTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Delete Old CI" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete Old CI?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Something changed first; the page shows what is there now.",
    );
    await waitFor(() => {
      expect(gets(seen, TOKENS)).toBe(2);
    });
  });

  it("says why the list could not be loaded", async () => {
    answerWith({ [`GET ${TOKENS}`]: { status: 503, body: { code: "UNAVAILABLE", detail: "<b>server text</b>" } } });
    renderPage(<PersonalTokens />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Your tokens could not be loaded. ExecBound is unavailable; try again shortly.",
    );
    expect(screen.queryByText(/server text/)).toBeNull();
  });

  it("says what a token is recorded as and lists what it cannot do", async () => {
    answerWith({ [`GET ${TOKENS}`]: { body: { tokens: [] } } });
    renderPage(<PersonalTokens />);
    expect(
      await screen.findByText(/every audit event it causes names you and the token/)
    ).toBeInTheDocument();
    const refused = screen.getByRole("list", { name: "What a token cannot do" });
    expect(within(refused).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "approve or deny a request",
      "settle an execution",
      "activate a policy or install the sample targets",
      "switch the workspace to observe-only",
      "lift an emergency stop",
      "reactivate an agent",
      "unarchive a space",
      "change approval rules or approvers",
      "invite people, or change people, access or sign-in",
      "revoke a key from the Credentials list (an agent's own page can)",
      "connect, re-key or revoke a monitoring connection, or mint, rotate or revoke a reporting source",
      "acknowledge several monitoring findings at once",
      "resolve a person's account request",
      "change your own account",
      "list, create, revoke or delete tokens",
      "read the browser session or switch its workspace or space",
    ]);
    expect(refused.nextElementSibling).toHaveTextContent(
      "The console API reference, at /api/console on the documentation site, marks for each operation whether a token may call it.",
    );
  });

  it("warns what a token issued to never expire outlives, and who can still end it", async () => {
    answerWith({ [`GET ${TOKENS}`]: { body: { tokens: [] } } });
    renderPage(<PersonalTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Create token" }));
    await user.selectOptions(await screen.findByLabelText("Lifetime"), "never");
    expect(
      screen.getByText(
        "A token that never expires keeps working until it is revoked, by you or by any administrator from Workspace settings. It also stops when you leave the workspace, stop being an administrator here, or your password is reset.",
      ),
    ).toBeInTheDocument();
  });

  it("keeps the tokens it read through a read that fails", async () => {
    let reads = 0;
    answerWith({ [`GET ${TOKENS}`]: () => (++reads === 1 ? { body: { tokens: [row] } } : UNAVAILABLE) });
    const { queryClient } = renderPage(<PersonalTokens />);
    expect(await screen.findByText("Coding agent on my laptop")).toBeInTheDocument();
    // What returning to the tab does to a stale list: it reads it again, and here that read fails.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: listOwnTokensQueryKey() });
    });
    expect(reads).toBe(2);
    expect(await screen.findByText(/Your tokens could not be loaded/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke Coding agent on my laptop" })).toBeInTheDocument();
  });

  it("keeps Try again, its reason and the focus on it while the tokens are read again", async () => {
    const out = heldReply();
    const forbidden: Reply = { status: 403, body: { code: "FORBIDDEN", detail: "x" } };
    const replies: Promise<Reply>[] = [Promise.resolve(forbidden), out.reply];
    let reads = 0;
    answerWith({ [`GET ${TOKENS}`]: () => replies[reads++] ?? UNAVAILABLE });
    renderPage(<PersonalTokens />);
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
    expect(screen.getByRole("alert")).toHaveTextContent("Your tokens could not be loaded. This is not yours to do.");
    out.send(UNAVAILABLE);
    await waitFor(() => {
      expect(button).not.toHaveAttribute("aria-disabled");
    });
    expect(button).toHaveFocus();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Your tokens could not be loaded. ExecBound is unavailable; try again shortly.",
    );
  });
});
