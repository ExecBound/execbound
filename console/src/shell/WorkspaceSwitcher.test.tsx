// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceItem } from "../api/types.gen";
import { forgetServerTime, noteServerTime } from "../lib/clock";
import { SessionContext, PLACEHOLDER } from "../lib/session";
import { resetWorkspace } from "../lib/workspace-context";
import { json, serve } from "../test/api";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";

const LIST = "/api/console/v1/session/workspaces";
const SWITCH = "/api/console/v1/session/workspace";
const tenant = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;

function item(n: number, name: string, changes: Partial<WorkspaceItem> = {}): WorkspaceItem {
  return {
    tenant_id: tenant(n), name, current: false, kind: "HUMAN_APPROVER", roles: ["viewer"], entry: "open",
    waiting_state: "counted", waiting: 0, next_lapse: null, last_entered_at: null, ...changes,
  };
}
function nth(list: HTMLElement[], index: number): HTMLElement {
  const found = list[index];
  if (found === undefined) throw new Error(`no option ${String(index)}`);
  return found;
}
const CURRENT = item(1, "Personal", { current: true, kind: "ADMIN", roles: [], waiting_state: "current", waiting: null });

afterEach(() => { vi.unstubAllGlobals(); resetWorkspace(); forgetServerTime(); window.localStorage.clear(); });

function provide(workspaces: WorkspaceItem[], answers: Record<string, unknown> = {}) {
  const calls = serve({ [LIST]: { workspaces }, ...answers });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SessionContext.Provider value={{ ...PLACEHOLDER, role: "VIEWER", canSwitchWorkspaces: true, tenant: { id: tenant(1), name: "Personal", detail: "" } }}>
        <WorkspaceSwitcher />
        <p>Elsewhere on the page</p>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
  return calls;
}

async function open() {
  await userEvent.click(screen.getByRole("button", { name: /^Workspace Personal/ }));
  return screen.findByRole("listbox", { name: "Workspaces" });
}

describe("the trigger", () => {
  it("is named by the workspace alone while nothing waits elsewhere", async () => {
    provide([CURRENT, item(2, "Team")]);
    await waitFor(() => { expect(screen.getByRole("button", { name: "Workspace Personal" })).toBeInTheDocument(); });
    expect(document.querySelector(".workspace-dot")).toBeNull();
    expect(screen.getByRole("button", { name: "Workspace Personal" })).toHaveAttribute("aria-haspopup", "listbox");
  });

  it("carries a dot and says so when approvals wait in another workspace", async () => {
    provide([CURRENT, item(2, "Team", { waiting: 2, next_lapse: "2026-10-09T12:04:00Z" })]);
    expect(await screen.findByRole("button", { name: "Workspace Personal, approvals waiting in another workspace" })).toBeInTheDocument();
    expect(document.querySelector(".workspace-dot")).toHaveAttribute("aria-hidden", "true");
  });

  it("counts the workspaces when more than one holds approvals", async () => {
    provide([CURRENT, item(2, "Team", { waiting: 1, next_lapse: "2026-10-09T12:04:00Z" }), item(3, "Other", { waiting: 4, next_lapse: "2026-10-09T12:04:00Z" })]);
    expect(await screen.findByRole("button", { name: "Workspace Personal, approvals waiting in 2 other workspaces" })).toBeInTheDocument();
  });
});

describe("the menu", () => {
  it("loads when it opens, names the current workspace first and selected, and posts nothing for it", async () => {
    const calls = provide([item(2, "Team <script>"), CURRENT]);
    const listbox = await open();
    const options = await within(listbox).findAllByRole("option");
    expect(options.map((option) => option.querySelector("strong")?.textContent)).toEqual(["Personal", "Team <script>"]);
    expect(options[0]).toHaveAttribute("aria-selected", "true");
    expect(options[0]).toHaveTextContent("Current");
    expect(options[0]).toHaveTextContent("Administrator");
    expect(options[1]).toHaveTextContent("Viewer");
    await userEvent.click(nth(options, 0));
    expect(calls.some((call) => call.method === "POST")).toBe(false);
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("offers a filter only past five workspaces", async () => {
    provide([CURRENT, item(2, "B"), item(3, "C"), item(4, "D"), item(5, "E")]);
    await open();
    expect(screen.queryByRole("textbox", { name: "Filter workspaces" })).toBeNull();
  });

  it("filters seven by name, moves with the arrows, and gives focus back on Escape", async () => {
    provide([CURRENT, item(2, "Contoso SOC"), item(3, "Fabrikam"), item(4, "Contoso Lab"), item(5, "D"), item(6, "E"), item(7, "F")]);
    await open();
    const filter = await screen.findByRole("textbox", { name: "Filter workspaces" });
    await waitFor(() => { expect(filter).toHaveFocus(); });
    await userEvent.type(filter, "contoso");
    const options = screen.getAllByRole("option");
    expect(options.map((option) => option.querySelector("strong")?.textContent)).toEqual(["Contoso SOC", "Contoso Lab"]);
    await userEvent.keyboard("{ArrowDown}");
    expect(options[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(options[1]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(options[0]).toHaveFocus();
    await userEvent.keyboard("{ArrowUp}");
    expect(options[1]).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(screen.getByRole("button", { name: /^Workspace Personal/ })).toHaveFocus();
  });

  it("closes on a press outside, leaving focus where it went", async () => {
    provide([CURRENT, item(2, "Team")]);
    await open();
    await userEvent.click(screen.getByText("Elsewhere on the page"));
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("switches by Enter, waits with every option held, and says where it is going", async () => {
    let answer: ((response: Response) => void) | null = null;
    const calls = provide([CURRENT, item(2, "Team"), item(3, "Other")], {
      [SWITCH]: () => new Promise<Response>((resolve) => { answer = resolve; }),
    });
    await open();
    const team = nth(await screen.findAllByRole("option"), 1);
    team.focus();
    await userEvent.keyboard("{Enter}");
    expect(await screen.findByRole("status")).toHaveTextContent("Opening Team.");
    for (const option of screen.getAllByRole("option")) expect(option).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(nth(screen.getAllByRole("option"), 2));
    await waitFor(() => { expect(answer).not.toBeNull(); });
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
    expect(calls.find((call) => call.method === "POST")?.body).toEqual({ tenant_id: tenant(2), section: "/" });
  });

  it("shows the client's own sentence when the switch is refused", async () => {
    provide([CURRENT, item(2, "Team <script>")], { [SWITCH]: () => json({ code: "DIRECTORY_REQUIRED" }, 403) });
    await open();
    await userEvent.click(nth(await screen.findAllByRole("option"), 1));
    expect(await screen.findByRole("alert")).toHaveTextContent("organization sign-in");
  });

  it("never posts a workspace only its directory sign-in opens", async () => {
    const calls = provide([CURRENT, item(2, "Directory only", { entry: "directory", waiting_state: "withheld", waiting: null })]);
    await open();
    const option = nth(await screen.findAllByRole("option"), 1);
    expect(option).toHaveAttribute("aria-disabled", "true");
    expect(option).toHaveTextContent("Opens only through your organization's sign-in");
    await userEvent.click(option);
    option.focus();
    await userEvent.keyboard("{Enter}");
    expect(calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("says what entering asks where the count is withheld", async () => {
    provide([
      CURRENT,
      item(2, "Asks a code", { entry: "factor", waiting_state: "withheld", waiting: null }),
      item(3, "Asks a set-up", { entry: "enrol", waiting_state: "withheld", waiting: null }),
    ]);
    await open();
    const options = await screen.findAllByRole("option");
    expect(options[1]).toHaveTextContent("Opens after you confirm your second factor");
    expect(options[2]).toHaveTextContent("Opens after you set up a second factor");
    expect(options[1]).not.toHaveTextContent("waiting");
  });

  it("says how many wait and how long the first has left, and under a minute once its minute has passed", async () => {
    noteServerTime(new Headers({ Date: "Fri, 09 Oct 2026 12:00:30 GMT" }));
    provide([
      CURRENT,
      item(2, "Soon", { waiting: 2, next_lapse: "2026-10-09T12:04:00Z" }),
      item(3, "Now", { waiting: 1, next_lapse: "2026-10-09T12:00:00Z" }),
      item(4, "Quiet", { waiting: 0 }),
    ]);
    await open();
    const options = await screen.findAllByRole("option");
    expect(options[1]).toHaveTextContent(/2 waiting for you · the first has .*left/);
    expect(options[1]?.querySelector("time")).toHaveAttribute("dateTime", "2026-10-09T12:04:00Z");
    expect(options[2]).toHaveTextContent("1 waiting for you · the first has under a minute left");
    expect(options[3]).not.toHaveTextContent("waiting");
  });
});
