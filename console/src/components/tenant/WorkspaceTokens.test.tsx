// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { listWorkspaceTokensQueryKey } from "../../api/@tanstack/react-query.gen";
import type { TokenRow } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, heldReply, type Reply, renderPage, type Seen, settle, UNAVAILABLE } from "../../test/page";
import { PersonalTokens } from "../settings/PersonalTokens";
import { WorkspaceTokens } from "./WorkspaceTokens";

const TOKENS = "/api/console/v1/tenant/tokens";
const OWN = "/api/console/v1/settings/tokens";
const CAPTION = "Personal access tokens in this workspace, newest first.";

const rows: TokenRow[] = [
  {
    token_id: "4b2c7a1e-0000-4000-8000-000000000001",
    credential_id: "4b2c7a1e-0000-4000-8000-000000000021",
    name: "Coding agent on my laptop",
    owner_id: "4b2c7a1e-0000-4000-8000-000000000010",
    owner_label: "Dana Reyes",
    created_at: "2026-09-25T12:00:00Z",
    expires_at: "2026-10-25T12:00:00Z",
    last_used_at: null,
    state: "live",
  },
  {
    token_id: "4b2c7a1e-0000-4000-8000-000000000002",
    credential_id: "4b2c7a1e-0000-4000-8000-000000000022",
    name: "CI runner",
    owner_id: "4b2c7a1e-0000-4000-8000-000000000011",
    owner_label: "A. Rivera",
    created_at: "2026-09-20T12:00:00Z",
    expires_at: "2026-10-20T12:00:00Z",
    last_used_at: "2026-09-26T08:00:00Z",
    state: "live",
  },
  // Names are the owner's own and repeat across administrators; a missing owner label reads
  // as Administrator.
  {
    token_id: "4b2c7a1e-0000-4000-8000-000000000003",
    credential_id: "4b2c7a1e-0000-4000-8000-000000000023",
    name: "CI runner",
    owner_id: "4b2c7a1e-0000-4000-8000-000000000012",
    owner_label: null,
    created_at: "2026-09-19T12:00:00Z",
    expires_at: "2026-10-19T12:00:00Z",
    last_used_at: null,
    state: "live",
  },
];

function gets(seen: Seen[], path = TOKENS): number {
  return seen.filter((request) => request.method === "GET" && request.path === path).length;
}

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

describe("WorkspaceTokens", () => {
  it("lists every administrator's tokens newest first and revokes one after confirmation", async () => {
    const [live, ...others] = rows;
    if (live === undefined) throw new Error("fixture");
    let first: TokenRow = live;
    const seen = answerWith({
      [`GET ${TOKENS}`]: () => ({ body: { tokens: [first, ...others] } }),
      [`GET ${OWN}`]: { body: { tokens: [] } },
      [`POST ${TOKENS}/${live.token_id}/revoke`]: () => {
        first = { ...live, state: "revoked" };
        return { body: { tokens: [first, ...others] } };
      },
    });
    renderPage(
      <>
        <WorkspaceTokens />
        <PersonalTokens />
      </>,
    );
    expect(await screen.findByText("Dana Reyes")).toBeInTheDocument();
    expect(screen.getByText("A. Rivera")).toBeInTheDocument();
    const user = userEvent.setup();
    const table = screen.getByRole("table", { name: CAPTION });
    const dana = within(table).getAllByRole("row")[1];
    if (dana === undefined) throw new Error("fixture");
    expect(dana).toHaveTextContent("Coding agent on my laptop");
    expect(within(table).getByRole("button", { name: "Revoke CI runner, A. Rivera" })).toBeInTheDocument();
    expect(within(table).getByRole("button", { name: "Revoke CI runner, Administrator" })).toBeInTheDocument();
    await user.click(within(dana).getByRole("button", { name: "Revoke Coding agent on my laptop, Dana Reyes" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke Coding agent on my laptop?" });
    expect(dialog).toHaveTextContent("Anything using it stops working at its next request.");
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(
      seen.filter((request) => request.method === "POST").map((request) => [request.path, request.body]),
    ).toEqual([[`${TOKENS}/${live.token_id}/revoke`, {}]]);
    expect(await screen.findByText("Token revoked.")).toBeInTheDocument();
    const revoked = within(screen.getByRole("table", { name: CAPTION })).getAllByRole("row")[1];
    if (revoked === undefined) throw new Error("fixture");
    expect(within(revoked).getByText("revoked")).toBeInTheDocument();
    expect(within(revoked).queryByRole("button")).toBeNull();
    // The row's button is gone, so the focus goes to the table rather than the page.
    await waitFor(() => {
      expect(document.activeElement).toBe(screen.getByRole("region", { name: CAPTION }));
    });
    // The answer is this card's fresh list, so only the other card's list is read again.
    await waitFor(() => {
      expect(gets(seen, OWN)).toBe(2);
    });
    expect(gets(seen)).toBe(1);
  });

  it("explains a failed revoke and reads the list again", async () => {
    const seen = answerWith({
      [`GET ${TOKENS}`]: { body: { tokens: rows } },
      [`POST ${TOKENS}/${rows[0]?.token_id ?? ""}/revoke`]: {
        status: 409,
        body: { code: "CONFLICT", detail: "<script>server text</script>" },
      },
    });
    renderPage(<WorkspaceTokens />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Revoke Coding agent on my laptop, Dana Reyes" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke Coding agent on my laptop?" });
    await user.click(within(dialog).getByRole("button", { name: "Revoke" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Something changed first; the page shows what is there now.",
    );
    expect(screen.queryByText(/server text/)).toBeNull();
    await waitFor(() => {
      expect(gets(seen)).toBe(2);
    });
  });

  it("says why the list could not be loaded", async () => {
    answerWith({ [`GET ${TOKENS}`]: { status: 403, body: { code: "FORBIDDEN", detail: "x" } } });
    renderPage(<WorkspaceTokens />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Personal access tokens could not be loaded. This is not yours to do.",
    );
  });

  it("keeps the tokens it read through a read that fails", async () => {
    let reads = 0;
    answerWith({ [`GET ${TOKENS}`]: () => (++reads === 1 ? { body: { tokens: rows } } : UNAVAILABLE) });
    const { queryClient } = renderPage(<WorkspaceTokens />);
    expect(await screen.findByRole("table", { name: CAPTION })).toBeInTheDocument();
    // What returning to the tab does to a stale list: it reads it again, and here that read fails.
    await act(async () => {
      await queryClient.refetchQueries({ queryKey: listWorkspaceTokensQueryKey() });
    });
    expect(reads).toBe(2);
    expect(await screen.findByText(/Personal access tokens could not be loaded/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: CAPTION })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke Coding agent on my laptop, Dana Reyes" })).toBeInTheDocument();
  });

  it("keeps Try again, its reason and the focus on it while the tokens are read again", async () => {
    const out = heldReply();
    const forbidden: Reply = { status: 403, body: { code: "FORBIDDEN", detail: "x" } };
    const replies: Promise<Reply>[] = [Promise.resolve(forbidden), out.reply];
    let reads = 0;
    answerWith({ [`GET ${TOKENS}`]: () => replies[reads++] ?? UNAVAILABLE });
    renderPage(<WorkspaceTokens />);
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
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Personal access tokens could not be loaded. This is not yours to do.",
    );
    out.send({ body: { tokens: rows } });
    expect(await screen.findByRole("table", { name: CAPTION })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });
});
