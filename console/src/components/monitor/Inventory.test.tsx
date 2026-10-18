// SPDX-License-Identifier: AGPL-3.0-only
// Report this story (MC19, MC22, #678): where this deployment mints sources, a discovered story
// with an open coverage gap offers to report it, opening Add a reporting source with its ID
// filled, and says that reporting is visibility and not governance. A story without a gap, or
// any story where sources are not minted here, offers nothing; the operator's command stays
// behind its own disclosure.

import { act, cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { MonitorSnapshot } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { withEdition } from "../../test/edition";
import { snapshot, story } from "../../test/monitor-data";
import { answerWith, heldReply, renderPage, settle } from "../../test/page";
import { minted, options, source, SPACE_A, SPACE_B } from "../../test/source-data";
import { Inventory } from "./Inventory";

const ADMIN: SessionSummary = { ...PLACEHOLDER, role: "ADMIN" };
const CONNECT = "GET /api/console/v1/monitor/connect";
const SOURCES = "/api/console/v1/monitor/sources";
const GAP = story({ external_id: "4002", name: "Unreported story", coverage_class: "discovered_only", coverage: "Discovered only", gap_opened_at: "2026-10-11T08:00:00+00:00", source_id: null });
const CLEAN = story({ external_id: "4003", name: "Covered story", source_id: null, gap_opened_at: null });
const MINTED_SOURCE = "5e5e5e5e-0000-4000-8000-0000000000c1";
const LAPSED_SOURCE = "5e5e5e5e-0000-4000-8000-0000000000b1";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function inventory(available: boolean, operatorCommands: boolean, data: MonitorSnapshot = snapshot({ stories: [GAP, CLEAN] })) {
  answerWith({ [CONNECT]: { body: available ? options() : options({ tines: "unconfigured", sources: "unconfigured" }) } });
  renderPage(withEdition(<Inventory data={data} />, { operatorCommands }), ADMIN);
  await settle();
  await settle();
}

function row(name: string): HTMLElement {
  const found = screen.getByText(name).closest<HTMLElement>("tr");
  if (found === null) throw new Error(`no row for ${name}`);
  return found;
}

describe("Report this story (MC19)", () => {
  it("offers a story with an open gap to be reported, with its ID filled, as visibility only", async () => {
    await inventory(true, false);
    const gap = row("Unreported story");
    expect(gap).toHaveTextContent("Report this story to see what it does. Reporting does not govern or block it.");
    await userEvent.click(within(gap).getByRole("button", { name: "Report this story" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    expect(within(dialog).getByLabelText("Tines story ID")).toHaveValue("4002");
    expect(within(row("Covered story")).queryByRole("button", { name: "Report this story" })).toBeNull();
  });

  it("waits ten minutes from each source's own token dialog closing, not from the first one's", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const FIRST = "5e5e5e5e-0000-4000-8000-0000000000a1";
    const SECOND = "5e5e5e5e-0000-4000-8000-0000000000a2";
    const OTHER = story({ ...GAP, external_id: "4004", name: "Another unreported story" });
    const made: [string, string][] = [
      [FIRST, "4002"],
      [SECOND, "4004"],
    ];
    const calls = answerWith({
      [CONNECT]: { body: options() },
      [`POST ${SOURCES}`]: () => {
        const [source_id, story_id] = made.shift() ?? [SECOND, "4004"];
        return { status: 201, body: minted({ source_id, story_id }) };
      },
      [`GET ${SOURCES}/${FIRST}`]: { body: source({ source_id: FIRST, story_id: "4002" }) },
      [`GET ${SOURCES}/${SECOND}`]: { body: source({ source_id: SECOND, story_id: "4004" }) },
    });
    renderPage(withEdition(<Inventory data={snapshot({ stories: [GAP, OTHER] })} />, { operatorCommands: false }), ADMIN);
    const report = async (name: string) => {
      await user.click(within(await screen.findByText(name).then((cell) => cell.closest("tr") as HTMLElement)).getByRole("button", { name: "Report this story" }));
      const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
      await user.click(within(dialog).getByRole("button", { name: "Create source" }));
      const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
      await user.click(within(shown).getByRole("button", { name: "I have copied it" }));
    };
    await report("Unreported story");
    expect(await screen.findByText("Waiting for the first heartbeat from story 4002…")).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(11 * 60_000);
    expect(await screen.findByText(/No heartbeat yet/)).toBeInTheDocument();
    await report("Another unreported story");
    expect(await screen.findByText("Waiting for the first heartbeat from story 4004…")).toBeInTheDocument();
    const second = () => calls.filter((call) => call.method === "GET" && call.path === `${SOURCES}/${SECOND}`).length;
    const before = second();
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => {
      expect(second()).toBeGreaterThan(before);
    });
    expect(screen.queryByText(/No heartbeat yet/)).toBeNull();
  });

  it("says the new source is reporting once the page's snapshot shows its first heartbeat, after the card's ten minutes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const silent = source({ source_id: MINTED_SOURCE, story_id: "4002" });
    // The card's own reads never see the heartbeat; only the page's snapshot, which polls on its
    // own every 30 seconds, does.
    answerWith({
      [CONNECT]: { body: options() },
      [`POST ${SOURCES}`]: { status: 201, body: minted({ source_id: MINTED_SOURCE, story_id: "4002" }) },
      [`GET ${SOURCES}/${MINTED_SOURCE}`]: { body: silent },
    });
    let poll: (data: MonitorSnapshot) => void = () => undefined;
    function Page() {
      const [data, setData] = useState<MonitorSnapshot>(snapshot({ stories: [GAP] }));
      poll = setData;
      return <Inventory data={data} />;
    }
    renderPage(withEdition(<Page />, { operatorCommands: false }), ADMIN);
    await user.click(within(await screen.findByText("Unreported story").then((cell) => cell.closest("tr") as HTMLElement)).getByRole("button", { name: "Report this story" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a reporting source" });
    await user.click(within(dialog).getByRole("button", { name: "Create source" }));
    const shown = await screen.findByRole("dialog", { name: "Copy the source token now" });
    await user.click(within(shown).getByRole("button", { name: "I have copied it" }));
    expect(await screen.findByText("Waiting for the first heartbeat from story 4002…")).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(11 * 60_000);
    expect(await screen.findByText(/^No heartbeat yet/)).toBeInTheDocument();
    act(() => {
      poll(
        snapshot({
          stories: [{ ...GAP, source_id: MINTED_SOURCE }],
          sources: [{ ...silent, coverage: "Reporting", last_heartbeat_at: "2026-10-12T12:12:00+00:00" }],
        }),
      );
    });
    const line = await screen.findByText(/^Reporting\. First heartbeat at/);
    expect(line.querySelector("time")).toHaveAttribute("dateTime", "2026-10-12T12:12:00+00:00");
    expect(screen.queryByText(/No heartbeat yet/)).toBeNull();
  });

  it("offers nothing in a Space this administrator only reviews", async () => {
    answerWith({ [CONNECT]: { body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: false } }) } });
    renderPage(withEdition(<Inventory data={snapshot({ stories: [GAP, CLEAN] })} />, { operatorCommands: false }), ADMIN);
    await settle();
    await settle();
    expect(screen.queryByRole("button", { name: "Report this story" })).toBeNull();
  });

  it("offers nothing until it has read where a source lands, once the session has moved to another Space", async () => {
    const held = heldReply();
    let reads = 0;
    answerWith({
      // Read while the session was in Customer B; another tab has since moved it to Customer A.
      [CONNECT]: () => {
        reads += 1;
        return reads === 1
          ? { body: options({ placement: { space_id: SPACE_B, name: "Customer B", archived: false, administered: true } }) }
          : held.reply;
      },
    });
    const moved: SessionSummary = { ...ADMIN, space: { id: SPACE_A, name: "Customer A", archived: false }, spaces: 2 };
    renderPage(withEdition(<Inventory data={snapshot({ stories: [GAP, CLEAN] })} />, { operatorCommands: false }), moved);
    await waitFor(() => {
      expect(reads).toBe(2);
    });
    await settle();
    expect(screen.queryByRole("button", { name: "Report this story" })).toBeNull();
    held.send({ body: options() });
    expect(await within(row("Unreported story")).findByRole("button", { name: "Report this story" })).toBeInTheDocument();
  });

  it("never tells anyone to rotate or revoke a source that can report, beside a gap only the next inventory pass closes", async () => {
    // Report this story has just minted it: the gap stays open until inventory is read again.
    const FRESH = story({ ...GAP, external_id: "4006", name: "Just reported story", source_id: MINTED_SOURCE });
    await inventory(true, true, snapshot({ stories: [FRESH] }));
    const fresh = row("Just reported story");
    expect(fresh).toHaveTextContent(MINTED_SOURCE);
    expect(fresh).toHaveTextContent("This source can report. The gap stays open until the next inventory pass reassesses the story.");
    // None of the words an expired source's row carries.
    expect(fresh).not.toHaveTextContent(/does not report|rotate|revoke|expired/i);
    expect(within(fresh).queryByRole("button", { name: "Report this story" })).toBeNull();
  });

  it("says a revoked connection's gap stays open beside a source that can report, since no inventory pass reassesses it", async () => {
    // The connection was revoked after the story's source was added: it is never collected
    // again, so its row keeps the gap it had.
    const KEPT = story({ ...GAP, external_id: "4009", name: "Story of a revoked connection", source_id: MINTED_SOURCE, connection_revoked: true });
    await inventory(true, true, snapshot({ stories: [KEPT] }));
    const kept = row("Story of a revoked connection");
    expect(kept).toHaveTextContent(MINTED_SOURCE);
    expect(kept).toHaveTextContent(
      "This source can report. This story's connection was revoked, so no inventory pass reassesses it and its gap stays open.",
    );
    expect(kept).not.toHaveTextContent(/next inventory pass|Rotate|revoke it|expired/);
  });

  it("says a story whose source's token has expired is not reported now, and where to renew it", async () => {
    const LAPSED = story({ ...GAP, external_id: "4005", name: "Lapsed story", source_id: LAPSED_SOURCE, source_expired: true });
    await inventory(true, false, snapshot({ stories: [LAPSED] }));
    const lapsed = row("Lapsed story");
    expect(lapsed).toHaveTextContent(LAPSED_SOURCE);
    expect(lapsed).toHaveTextContent(
      "Its token has expired, so it does not report this story now. Rotate its token or revoke it on Connections.",
    );
    expect(within(lapsed).queryByRole("button", { name: "Report this story" })).toBeNull();
  });

  it("sends an expired source's administrator to rotate-source where the console mints nothing", async () => {
    const LAPSED = story({ ...GAP, external_id: "4005", name: "Lapsed story", source_id: LAPSED_SOURCE, source_expired: true });
    await inventory(false, true, snapshot({ stories: [LAPSED] }));
    expect(row("Lapsed story")).toHaveTextContent(
      "Its token has expired, so it does not report this story now. Rotate its token with rotate-source, or revoke it on Connections.",
    );
  });

  it("says no more than that where neither the console nor a command renews an expired source", async () => {
    const LAPSED = story({ ...GAP, external_id: "4005", name: "Lapsed story", source_id: LAPSED_SOURCE, source_expired: true });
    await inventory(false, false, snapshot({ stories: [LAPSED] }));
    const lapsed = row("Lapsed story");
    expect(lapsed).toHaveTextContent("Its token has expired, so it does not report this story now.");
    expect(lapsed).not.toHaveTextContent(/Rotate|Connections/);
  });

  it("tells an administrator who only reviews an expired source's Space that its administrators renew it", async () => {
    const LAPSED = story({ ...GAP, external_id: "4005", name: "Lapsed story", source_id: LAPSED_SOURCE, source_expired: true });
    const reviewed = source({ source_id: LAPSED_SOURCE, story_id: "4005", expires_at: "2026-10-01T12:00:00+00:00", coverage: "Expired", administered: false });
    for (const [available, operatorCommands] of [
      [true, false],
      [false, true],
    ] as const) {
      answerWith({ [CONNECT]: { body: available ? options() : options({ tines: "unconfigured", sources: "unconfigured" }) } });
      const { unmount } = renderPage(withEdition(<Inventory data={snapshot({ stories: [LAPSED], sources: [reviewed] })} />, { operatorCommands }), ADMIN);
      await settle();
      await settle();
      const lapsed = row("Lapsed story");
      expect(lapsed).toHaveTextContent(
        "Its token has expired, so it does not report this story now. You review its Space but do not administer it, so its administrators rotate or revoke it.",
      );
      expect(lapsed).not.toHaveTextContent(/on Connections|rotate-source/);
      unmount();
    }
  });

  it("names a source beside an open gap in a Space this reader does not see by its identifier alone", async () => {
    // The server never says whether such a source's token has expired; were it to, the row still
    // says nothing about it and offers nothing, since the source is another Space's.
    for (const expired of [false, true]) {
      const HIDDEN = story({ ...GAP, external_id: "4007", name: "Story reported elsewhere", source_id: LAPSED_SOURCE, source_expired: expired, source_visible: false });
      await inventory(true, true, snapshot({ stories: [HIDDEN] }));
      const hidden = row("Story reported elsewhere");
      expect(hidden).toHaveTextContent(LAPSED_SOURCE);
      expect(hidden).not.toHaveTextContent(/expired|Space you do not see|Rotate|revoke|gap stays open/);
      expect(within(hidden).queryByRole("button", { name: "Report this story" })).toBeNull();
      expect(within(hidden).queryByRole("button", { name: "Show the command to report this story" })).toBeNull();
      cleanup();
    }
  });

  it("names a source with no gap open in a Space this reader does not see by its identifier alone", async () => {
    // With no gap open, only an expired token would add anything to the row, so the source is
    // called expired here: were the server to say so of another Space's source, the row still
    // says nothing about it and offers nothing.
    const ELSEWHERE = story({ external_id: "4008", name: "Story covered elsewhere", source_id: LAPSED_SOURCE, source_expired: true, source_visible: false });
    await inventory(true, true, snapshot({ stories: [ELSEWHERE] }));
    const elsewhere = row("Story covered elsewhere");
    expect(elsewhere).toHaveTextContent(LAPSED_SOURCE);
    expect(elsewhere).not.toHaveTextContent(/expired|Rotate|revoke|administrators|gap stays open/);
    expect(within(elsewhere).queryByRole("button", { name: "Report this story" })).toBeNull();
    expect(within(elsewhere).queryByRole("button", { name: "Show the command to report this story" })).toBeNull();
  });

  it("offers nothing where this deployment mints no sources (MC22)", async () => {
    await inventory(false, false);
    expect(screen.queryByRole("button", { name: "Report this story" })).toBeNull();
    expect(screen.queryByText(/Reporting does not govern or block it/)).toBeNull();
  });

  it("keeps the operator's command behind its own disclosure", async () => {
    await inventory(true, true);
    const gap = row("Unreported story");
    expect(within(gap).getByRole("button", { name: "Report this story" })).toBeInTheDocument();
    expect(within(gap).queryByLabelText("Report command")).toBeNull();
    await userEvent.click(within(gap).getByRole("button", { name: "Show the command to report this story" }));
    expect(within(gap).getByLabelText("Report command")).toHaveTextContent("create-source");
  });
});
