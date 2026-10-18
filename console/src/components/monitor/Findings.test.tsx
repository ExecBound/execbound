// SPDX-License-Identifier: AGPL-3.0-only
import { focusManager } from "@tanstack/react-query";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { MonitorFinding } from "../../api/types.gen";
import { clearToasts } from "../../lib/toast";
import { answerWith, type Seen } from "../../test/page";
import { renderMonitor } from "../../test/monitor";
import { FINDING, findings, GAP, HEALTH, OBSERVED, REACH, snapshot } from "../../test/monitor-data";

const LIST = "GET /api/console/v1/monitor/findings";
const scrolled = vi.fn();

beforeEach(() => {
  scrolled.mockReset();
  Element.prototype.scrollIntoView = scrolled;
});

afterEach(() => {
  focusManager.setFocused(undefined);
  vi.unstubAllGlobals();
  vi.useRealTimers();
  clearToasts();
});

function reads(seen: Seen[], path: string): number {
  return seen.filter((request) => request.method === "GET" && request.path === path).length;
}

async function row(title: string): Promise<HTMLElement> {
  const found = (await screen.findByText(title)).closest("li");
  if (found === null) throw new Error(`No row for ${title}`);
  return found;
}

describe("the Findings queue (MQ4 to MQ6, #678)", () => {
  it("reads its own route, never the snapshot, and asks again only on focus", async () => {
    const seen = answerWith({ [LIST]: { body: findings() } });
    renderMonitor("/monitor?view=findings");
    expect(await screen.findByText(OBSERVED.title)).toBeInTheDocument();
    expect(reads(seen, "/api/console/v1/monitor/findings")).toBe(1);
    expect(reads(seen, "/api/console/v1/monitor")).toBe(0);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(reads(seen, "/api/console/v1/monitor/findings")).toBe(1);
    // The query client's own focus handling, which a tab regaining focus drives.
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    await waitFor(() => {
      expect(reads(seen, "/api/console/v1/monitor/findings")).toBe(2);
    });
  });

  it("filters by state with chips that keep the focus, and says what an empty state does not establish", async () => {
    const seen = answerWith({ [LIST]: { body: findings({ findings: [] }) } });
    const { router } = renderMonitor("/monitor?view=findings");
    const chips = await screen.findByRole("group", { name: "Findings to show" });
    expect(within(chips).getByRole("button", { name: "Open (2)" })).toHaveAttribute("aria-pressed", "true");
    expect(within(chips).getByRole("button", { name: "Acknowledged (1)" })).toBeInTheDocument();
    expect(within(chips).getByRole("button", { name: "All" })).toBeInTheDocument();
    expect(screen.getByText("No open findings")).toBeInTheDocument();
    expect(screen.getByText(/does not establish that no external activity occurred/)).toBeInTheDocument();
    const acknowledged = within(chips).getByRole("button", { name: "Acknowledged (1)" });
    await userEvent.click(acknowledged);
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ view: "findings", state: "acknowledged" });
    });
    expect(document.activeElement).toBe(acknowledged);
    await waitFor(() => {
      expect(seen.some((request) => request.path === "/api/console/v1/monitor/findings" && request.method === "GET")).toBe(true);
    });
    expect(await screen.findByText("No acknowledged findings")).toBeInTheDocument();
  });

  it("names what each finding is about, and renders every string as text", async () => {
    answerWith({ [LIST]: { body: findings({ findings: [REACH, HEALTH, GAP, OBSERVED] }) } });
    renderMonitor(`/monitor?view=findings&open=${REACH.finding_id}`);
    const agent = await row(REACH.title);
    expect(within(agent).getByRole("link", { name: "<img src=x> payroll" })).toHaveAttribute("href", `/monitor/agents/${REACH.agent?.agent_id ?? ""}`);
    expect(document.querySelector("img")).toBeNull();
    expect(within(agent).getByText("Nobody")).toBeInTheDocument();
    expect(within(agent).getByText(/what the directory says this agent can reach/)).toBeInTheDocument();
    await userEvent.click(within(await row(HEALTH.title)).getByRole("button", { name: "Show details" }));
    expect(await within(await row(HEALTH.title)).findByText("Synthetic <b>Tines</b> tenant")).toBeInTheDocument();
    expect(document.querySelector("b")).toBeNull();
    expect(within(await row(HEALTH.title)).getByText(/collection or reporting health, not about an action/)).toBeInTheDocument();
    await userEvent.click(within(await row(GAP.title)).getByRole("button", { name: "Show details" }));
    expect(await within(await row(GAP.title)).findByRole("link", { name: "Inventory" })).toHaveAttribute("href", "/monitor?view=inventory");
    await userEvent.click(within(await row(OBSERVED.title)).getByRole("button", { name: "Show details" }));
    const observed = await row(OBSERVED.title);
    expect(await within(observed).findByText("Story / reported action")).toBeInTheDocument();
    expect(within(observed).getByText("Target reference")).toBeInTheDocument();
    expect(within(observed).getByText(/source-reported activity/)).toBeInTheDocument();
  });

  it("names an agent's sponsors by their number", async () => {
    if (REACH.agent === null) throw new Error("fixture");
    const sponsored: MonitorFinding = { ...REACH, agent: { ...REACH.agent, sponsor_state: "present", sponsor_count: 2 } };
    answerWith({ [LIST]: { body: findings({ findings: [sponsored] }) } });
    renderMonitor(`/monitor?view=findings&open=${REACH.finding_id}`);
    expect(await screen.findByText("2 sponsors")).toBeInTheDocument();
  });

  it("opens a finding named in the address, and writes the one opened by hand", async () => {
    answerWith({ [LIST]: { body: findings({ findings: [OBSERVED, HEALTH] }) } });
    const { router } = renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    const toggle = await within(await row(OBSERVED.title)).findByRole("button", { name: "Hide details" });
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById(toggle.getAttribute("aria-controls") ?? "")).not.toBeNull();
    await waitFor(() => {
      expect(scrolled).toHaveBeenCalled();
    });
    await userEvent.click(within(await row(HEALTH.title)).getByRole("button", { name: "Show details" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ view: "findings", open: HEALTH.finding_id });
    });
    expect(within(await row(HEALTH.title)).getByRole("button", { name: "Hide details" })).toHaveAttribute("aria-expanded", "true");
  });

  it("reads a finding the list does not hold, and says when it cannot", async () => {
    const elsewhere = { ...HEALTH, finding_id: "f1f1f1f1-0000-4000-8000-000000000009", title: "From another state" };
    const seen = answerWith({
      [LIST]: { body: findings() },
      [`GET /api/console/v1/monitor/findings/${elsewhere.finding_id}`]: { body: elsewhere },
    });
    renderMonitor(`/monitor?view=findings&open=${elsewhere.finding_id}`);
    const pinned = await screen.findByRole("region", { name: "Opened from a link" });
    expect(await within(pinned).findByText("From another state")).toBeInTheDocument();
    expect(seen.some((request) => request.path === `/api/console/v1/monitor/findings/${elsewhere.finding_id}`)).toBe(true);
  });

  it("says a finding named in the address is not in this space or does not exist", async () => {
    answerWith({ [LIST]: { body: findings() } });
    renderMonitor("/monitor?view=findings&open=f1f1f1f1-0000-4000-8000-00000000000a");
    expect(
      await screen.findByText(
        "This finding is not in the space you are viewing, or it does not exist. Switch to All spaces to look again.",
      ),
    ).toBeInTheDocument();
  });

  it("acknowledges only through the server, then asks the reads again", async () => {
    let acknowledged = false;
    const seen = answerWith({
      [LIST]: () => ({
        body: findings({
          findings: [
            acknowledged
              ? {
                  ...OBSERVED,
                  acknowledged_at: "2026-09-19T05:10:00+00:00",
                  acknowledged_by: "0a1b2c3d-0000-4000-8000-000000000009",
                  acknowledged_by_ref: { principal_id: "0a1b2c3d-0000-4000-8000-000000000009", kind: "ADMIN", label: "Dana Reyes", number: 1 },
                }
              : OBSERVED,
          ],
        }),
      }),
      [`POST /api/console/v1/monitor/findings/${FINDING}/acknowledge`]: () => {
        acknowledged = true;
        return { body: snapshot({ open_findings: 0 }) };
      },
    });
    const { queryClient } = renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    const invalidated = vi.spyOn(queryClient, "invalidateQueries");
    await userEvent.click(await screen.findByRole("button", { name: "Acknowledge finding" }));
    expect(await screen.findByText(/Acknowledged/, { selector: "p" })).toHaveTextContent("by Dana Reyes User 1.");
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.body).toEqual({});
    const keys = invalidated.mock.calls.map(([filters]) => JSON.stringify(filters?.queryKey ?? "predicate"));
    expect(keys.some((key) => key.includes("readMonitor\""))).toBe(true);
    expect(keys.some((key) => key.includes("readTenant"))).toBe(true);
    expect(keys).toContain('"predicate"');
    expect(screen.getByRole("status")).toHaveTextContent("Finding acknowledged.");
  });

  it("keeps a refused acknowledgement open with the code's copy", async () => {
    answerWith({
      [LIST]: { body: findings() },
      [`POST /api/console/v1/monitor/findings/${FINDING}/acknowledge`]: { status: 404, body: { code: "NOT_FOUND", detail: "x" } },
    });
    renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    await userEvent.click(await screen.findByRole("button", { name: "Acknowledge finding" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("There is nothing here.");
    expect(within(await row(OBSERVED.title)).getByText("Open")).toBeInTheDocument();
  });
});

const ACKNOWLEDGE = `POST /api/console/v1/monitor/findings/${FINDING}/acknowledge`;
const BULK = "POST /api/console/v1/monitor/findings/acknowledge";
const DANA = { principal_id: "0a1b2c3d-0000-4000-8000-000000000009", kind: "ADMIN" as const, label: "Dana Reyes", number: 1 };

function acknowledgedAs(finding: MonitorFinding, note: string | null): MonitorFinding {
  return {
    ...finding,
    acknowledged_at: "2026-09-19T05:10:00+00:00",
    acknowledged_by: DANA.principal_id,
    acknowledged_by_ref: DANA,
    acknowledgement_note: note,
  };
}

describe("a note on an acknowledgement (MQ13, #678)", () => {
  it("posts the note and shows it, as text, under the acknowledgement", async () => {
    let note: string | null = null;
    const seen = answerWith({
      [LIST]: () => ({ body: findings({ findings: [note === null ? OBSERVED : acknowledgedAs(OBSERVED, note)] }) }),
      [ACKNOWLEDGE]: (request) => {
        note = (request.body as { note: string }).note;
        return { body: snapshot({ open_findings: 0 }) };
      },
    });
    renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    const typed = "Checked with the SOC lead. <b>fine</b>";
    await userEvent.type(await screen.findByRole("textbox", { name: "Note (optional)" }), typed);
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge finding" }));
    expect(await screen.findByText(`Note: ${typed}`)).toBeInTheDocument();
    expect(document.querySelector(".finding-body b")).toBeNull();
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.body).toEqual({ note: typed });
  });

  it("says a secret-shaped note was refused and keeps what was typed", async () => {
    answerWith({
      [LIST]: { body: findings() },
      [ACKNOWLEDGE]: { status: 400, body: { code: "INVALID_BODY", detail: "x", fields: ["note"] } },
    });
    renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    const field = await screen.findByRole("textbox", { name: "Note (optional)" });
    await userEvent.type(field, "sk_live_not_really");
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge finding" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("A note must not look like a password, key or token.");
    expect(field).toHaveValue("sk_live_not_really");
  });

  it("says when someone acknowledged first and the note was not saved", async () => {
    answerWith({
      [LIST]: { body: findings() },
      [ACKNOWLEDGE]: { status: 409, body: { code: "CONFLICT", detail: "x" } },
    });
    renderMonitor(`/monitor?view=findings&open=${FINDING}`);
    await userEvent.type(await screen.findByRole("textbox", { name: "Note (optional)" }), "Late.");
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge finding" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Someone acknowledged this finding first; your note was not saved.");
  });
});

describe("bulk acknowledgement, confirmed in place (MQ14, #678)", () => {
  const OTHER: MonitorFinding = { ...HEALTH, title: "Collection stopped" };
  const THIRD: MonitorFinding = { ...GAP, title: "Story without a source" };

  async function check(title: string) {
    await userEvent.click(within(await row(title)).getByRole("checkbox", { name: `Select ${title}` }));
  }

  it("sends nothing until the count is confirmed, and Cancel or a new selection sends nothing", async () => {
    const seen = answerWith({ [LIST]: { body: findings({ findings: [OBSERVED, OTHER, THIRD] }) } });
    renderMonitor("/monitor?view=findings");
    await check(OBSERVED.title);
    await check(OTHER.title);
    const ask = screen.getByRole("button", { name: "Acknowledge selected (2)" });
    await userEvent.click(ask);
    expect(screen.getByText("Acknowledge 2 findings? An acknowledgement cannot be undone.")).toBeInTheDocument();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Acknowledge 2 findings" }));
    expect(screen.queryByRole("button", { name: "Acknowledge selected (2)" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/An acknowledgement cannot be undone/)).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Acknowledge selected (2)" }));
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge selected (2)" }));
    await check(THIRD.title);
    expect(screen.queryByText(/An acknowledgement cannot be undone/)).toBeNull();
    expect(screen.getByRole("button", { name: "Acknowledge selected (3)" })).toBeInTheDocument();
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("posts once on confirmation and reports each outcome with its title", async () => {
    const seen = answerWith({
      [LIST]: { body: findings({ findings: [OBSERVED, OTHER] }) },
      [BULK]: {
        body: {
          results: [
            { finding_id: OBSERVED.finding_id, outcome: "acknowledged" },
            { finding_id: OTHER.finding_id, outcome: "unavailable" },
          ],
        },
      },
    });
    const { queryClient } = renderMonitor("/monitor?view=findings");
    const invalidated = vi.spyOn(queryClient, "invalidateQueries");
    await check(OBSERVED.title);
    await check(OTHER.title);
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge selected (2)" }));
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge 2 findings" }));
    const results = await screen.findByRole("status", { name: "Acknowledgement results" });
    expect(results).toHaveTextContent("Acknowledged 1. 1 is not in the space you are viewing or no longer exists.");
    expect(results).not.toHaveTextContent("Your note was saved only");
    expect(within(results).getByText(OBSERVED.title)).toBeInTheDocument();
    expect(within(results).getByText(OTHER.title)).toBeInTheDocument();
    const posted = seen.filter((request) => request.method === "POST");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.body).toEqual({ finding_ids: [OBSERVED.finding_id, OTHER.finding_id] });
    const keys = invalidated.mock.calls.map(([filters]) => JSON.stringify(filters?.queryKey ?? "predicate"));
    expect(keys.some((key) => key.includes("readMonitor\""))).toBe(true);
    expect(keys.some((key) => key.includes("readTenant"))).toBe(true);
    expect(keys).toContain('"predicate"');
  });

  it("says a shared note was saved only on the findings acknowledged now", async () => {
    const seen = answerWith({
      [LIST]: { body: findings({ findings: [OBSERVED, OTHER] }) },
      [BULK]: {
        body: {
          results: [
            { finding_id: OBSERVED.finding_id, outcome: "acknowledged" },
            { finding_id: OTHER.finding_id, outcome: "already_acknowledged" },
          ],
        },
      },
    });
    renderMonitor("/monitor?view=findings");
    await userEvent.type(await screen.findByRole("textbox", { name: "Note for the selected findings (optional)" }), "Batch reviewed.");
    await check(OBSERVED.title);
    await check(OTHER.title);
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge selected (2)" }));
    await userEvent.click(screen.getByRole("button", { name: "Acknowledge 2 findings" }));
    const results = await screen.findByRole("status", { name: "Acknowledgement results" });
    expect(results).toHaveTextContent(
      "Acknowledged 1. 1 was already acknowledged. Your note was saved only on the findings acknowledged now.",
    );
    expect(seen.find((request) => request.method === "POST")?.body).toEqual({
      finding_ids: [OBSERVED.finding_id, OTHER.finding_id],
      note: "Batch reviewed.",
    });
  });

  it("selects at most fifty open findings on the page", async () => {
    const many = Array.from({ length: 60 }, (_, index) => ({
      ...OBSERVED,
      finding_id: `f1f1f1f1-0000-4000-8000-${String(index + 100).padStart(12, "0")}`,
      title: `Finding ${String(index)}`,
    }));
    const done = acknowledgedAs({ ...OTHER, finding_id: "f1f1f1f1-0000-4000-8000-000000000999" }, null);
    answerWith({ [LIST]: { body: findings({ findings: [done, ...many] }) } });
    renderMonitor("/monitor?view=findings&state=all");
    await userEvent.click(await screen.findByRole("button", { name: "Select all open on this page" }));
    expect(screen.getByRole("button", { name: "Acknowledge selected (50)" })).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox", { checked: true })).toHaveLength(50);
    expect(within(await row(done.title)).queryByRole("checkbox")).toBeNull();
  });
});
