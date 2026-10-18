// SPDX-License-Identifier: AGPL-3.0-only
// A reporting source's actions (MC15, MC22, #678): Rotate offers the grace and shows the new
// token once; Revoke asks first and is offered whether or not this deployment mints sources;
// a revoked source offers neither.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { readMonitorQueryKey } from "../../api/@tanstack/react-query.gen";
import type { MonitorSource } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { clearToasts } from "../../lib/toast";
import { answerWith, keptNowhere, renderPage, settle } from "../../test/page";
import { minted, SOURCE, source, TOKEN } from "../../test/source-data";
import { SourceActions } from "./SourceActions";

const PATH = `/api/console/v1/monitor/sources/${SOURCE}`;
const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };

afterEach(() => {
  vi.unstubAllGlobals();
  clearToasts();
});

async function actions(row: MonitorSource, available: boolean, routes: Parameters<typeof answerWith>[0] = {}) {
  const calls = answerWith(routes);
  const rendered = renderPage(<SourceActions source={row} mintAvailable={available} />, ADMIN);
  await settle();
  return { ...rendered, calls };
}

describe("a reporting source's actions (MC15)", () => {
  it("rotates with the chosen grace and shows the new token once", async () => {
    const { calls, queryClient } = await actions(source(), true, {
      [`POST ${PATH}/rotate`]: { body: minted({ previous_valid_until: "2026-10-12T12:30:00+00:00" }) },
    });
    await userEvent.click(screen.getByRole("button", { name: "Rotate token" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate the source token" });
    const grace = within(dialog).getByLabelText("Keep the previous token reporting for");
    expect(within(grace).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "No time: stop it now",
      "10 minutes",
      "30 minutes",
      "1 hour",
    ]);
    await userEvent.selectOptions(grace, "30");
    await userEvent.click(within(dialog).getByRole("button", { name: "Rotate token" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    expect(within(shown).getByLabelText(/Source token/)).toHaveValue(TOKEN);
    expect(shown).toHaveTextContent(/The previous token keeps reporting until/);
    expect(calls.filter((call) => call.method === "POST").map((call) => [call.path, call.body])).toEqual([
      [`${PATH}/rotate`, { lifetime_days: 30, grace_minutes: 30 }],
    ]);
    await userEvent.click(within(shown).getByRole("button", { name: "I have copied it" }));
    await keptNowhere(queryClient, TOKEN);
  });

  it("warns that rotating stops at once a previous token still within its grace, above the grace it informs", async () => {
    const until = new Date(Date.now() + 20 * 60_000).toISOString();
    await actions(source({ previous_valid_until: until }), true);
    await userEvent.click(screen.getByRole("button", { name: "Rotate token" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate the source token" });
    const warning = within(dialog).getByText(/The token this source replaced is still accepted until/);
    expect(warning).toHaveTextContent(
      /Rotating again stops it now: only the token the source holds now keeps reporting, for the time you choose below\./,
    );
    expect(warning.querySelector("time")).toHaveAttribute("dateTime", until);
    // "Below" is the grace select: the warning sits after the token's lifetime and before the
    // grace, so it is read before the choice it bears on.
    const lifetime = within(dialog).getByLabelText("New token valid for");
    const grace = within(dialog).getByLabelText("Keep the previous token reporting for");
    expect(lifetime.compareDocumentPosition(warning) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(warning.compareDocumentPosition(grace) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("gives no such warning once the previous token's grace has ended", async () => {
    await actions(source({ previous_valid_until: "2020-01-01T00:00:00+00:00" }), true);
    await userEvent.click(screen.getByRole("button", { name: "Rotate token" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate the source token" });
    expect(dialog).not.toHaveTextContent(/still accepted until/);
  });

  it("never says nothing was changed when a rotation's answer did not arrive", async () => {
    const { queryClient } = await actions(source(), true, {
      [`POST ${PATH}/rotate`]: { status: 503, body: { code: "UNAVAILABLE", detail: "x" } },
    });
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    await userEvent.click(screen.getByRole("button", { name: "Rotate token" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate the source token" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Rotate token" }));
    expect(
      await within(dialog).findByText(
        "ExecBound did not confirm the rotation, so a new token may have been issued and the previous one may stop at the end of the grace you chose. If the source's expiry on Connections has changed, rotate again to get a token you hold.",
      ),
    ).toBeInTheDocument();
    expect(invalidate).toHaveBeenCalledWith({ queryKey: readMonitorQueryKey() });
  });

  it("asks before revoking, and sends nothing until confirmed", async () => {
    const { calls } = await actions(source(), true, { [`POST ${PATH}/revoke`]: { body: source({ revoked_at: "2026-10-12T12:00:00+00:00", coverage: "Disabled" }) } });
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke this source?" });
    expect(dialog).toHaveTextContent("The story's events will be refused from now on. A revoked source cannot be rotated.");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke source" }));
    await waitFor(() => {
      expect(calls.filter((call) => call.method === "POST").map((call) => call.path)).toEqual([`${PATH}/revoke`]);
    });
  });

  it("reads the sources again when a revocation's answer did not arrive, and never says nothing changed", async () => {
    const { queryClient } = await actions(source(), true, {
      [`POST ${PATH}/revoke`]: { status: 503, body: { code: "UNAVAILABLE", detail: "x" } },
    });
    const invalidate = vi.spyOn(queryClient, "invalidateQueries");
    await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke this source?" });
    await userEvent.click(within(dialog).getByRole("button", { name: "Revoke source" }));
    expect(
      await within(dialog).findByText(
        "ExecBound did not confirm the revocation, so it may have taken effect. Check the source on Connections before trying again.",
      ),
    ).toBeInTheDocument();
    expect(invalidate).toHaveBeenCalledWith({ queryKey: readMonitorQueryKey() });
  });

  it("offers Revoke but not Rotate where this deployment mints no sources (MC22)", async () => {
    await actions(source(), false);
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rotate token" })).toBeNull();
  });

  it("offers no change to a source in a Space this administrator only reviews, and says why", async () => {
    await actions(source({ administered: false }), true);
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Rotate token" })).toBeNull();
    expect(screen.getByText("You review this source's Space but do not administer it, so its administrators rotate or revoke it.")).toBeInTheDocument();
  });

  it("says a source that has kept its 10,000 events is replaced by adding the story first, and revoked only after", async () => {
    await actions(source({ accepted_count: 10_000, last_refusal_code: "SOURCE_CAPACITY" }), true);
    // Revoking is final and stops its heartbeats, and a full workspace refuses the story's next
    // source, so the card never says to revoke before the replacement exists.
    expect(
      screen.getByText(
        "This source has kept its 10,000 events, so intake refuses the story's further events, though it still takes the story's heartbeats, and rotating its token does not reset that count. To report story 4001's events again, add a reporting source for the story first, then revoke this one once the story reports through the new token. Where the workspace is full, adding is refused and this source carries on as it is.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/revoke this source, then add/)).toBeNull();
    // Rotation still works for it: its heartbeats and its token's life are unchanged.
    expect(screen.getByRole("button", { name: "Rotate token" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("says nothing of the limit for a source that has room", async () => {
    await actions(source({ accepted_count: 9_999 }), true);
    expect(screen.queryByText(/kept its 10,000 events/)).toBeNull();
  });

  it("offers nothing for a revoked source", async () => {
    await actions(source({ revoked_at: "2026-10-12T12:00:00+00:00", coverage: "Disabled" }), true);
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Rotate token" })).toBeNull();
  });
});
