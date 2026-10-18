// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Command } from "cmdk";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceItem } from "../api/types.gen";
import { PLACEHOLDER, SessionContext } from "../lib/session";
import { resetWorkspace } from "../lib/workspace-context";
import { json, serve } from "../test/api";
import { WorkspacePaletteGroup } from "./WorkspacePaletteGroup";

const LIST = "/api/console/v1/session/workspaces";
const SWITCH = "/api/console/v1/session/workspace";
const tenant = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;
const item = (n: number, name: string, current = false): WorkspaceItem => ({
  tenant_id: tenant(n), name, current, kind: "HUMAN_APPROVER", roles: ["viewer"], entry: "open",
  waiting_state: current ? "current" : "counted", waiting: current ? null : 0, next_lapse: null, last_entered_at: null,
});
const THREE = [item(1, "Personal", true), item(2, "Contoso SOC"), item(3, "Fabrikam")];

afterEach(() => { vi.unstubAllGlobals(); resetWorkspace(); window.history.replaceState(null, "", "/"); });

function Palette({ query }: { query: string }) {
  return (
    <SessionContext.Provider value={{ ...PLACEHOLDER, canSwitchWorkspaces: true, tenant: { id: tenant(1), name: "Personal", detail: "" } }}>
      <Command label="Search" shouldFilter={false}>
        <Command.List>
          <WorkspacePaletteGroup query={query} />
        </Command.List>
      </Command>
    </SessionContext.Provider>
  );
}

function provide(workspaces: WorkspaceItem[], answers: Record<string, unknown> = {}, query = "") {
  const calls = serve({ [LIST]: { workspaces }, ...answers });
  const view = render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <Palette query={query} />
    </QueryClientProvider>,
  );
  return { calls, view };
}

const posts = (calls: { method: string }[]) => calls.filter((call) => call.method === "POST");

describe("the palette's workspaces", () => {
  it("are absent for a single workspace", async () => {
    const { calls } = provide([item(1, "Personal", true)]);
    await waitFor(() => { expect(calls.length).toBeGreaterThan(0); });
    expect(screen.queryByRole("group", { name: "Workspaces" })).toBeNull();
  });

  it("list the others to switch to and the current one, which cannot be chosen", async () => {
    provide(THREE);
    const group = await screen.findByRole("group", { name: "Workspaces" });
    const options = within(group).getAllByRole("option");
    expect(options.map((option) => option.textContent)).toEqual(["Personal (current)", "Switch to Contoso SOC", "Switch to Fabrikam"]);
    expect(options[0]).toHaveAttribute("aria-disabled", "true");
  });

  it("are filtered by the typed words", async () => {
    provide(THREE, {}, "fab");
    const group = await screen.findByRole("group", { name: "Workspaces" });
    expect(within(group).getAllByRole("option").map((option) => option.textContent)).toEqual(["Switch to Fabrikam"]);
  });

  it("switch once, with the current section, holding every item and saying where", async () => {
    window.history.replaceState(null, "", "/activity");
    const held: { answer?: (response: Response) => void } = {};
    const { calls } = provide(THREE, { [SWITCH]: () => new Promise<Response>((resolve) => { held.answer = resolve; }) });
    const group = await screen.findByRole("group", { name: "Workspaces" });
    await userEvent.click(within(group).getByRole("option", { name: "Switch to Contoso SOC" }));
    expect(await within(group).findByRole("status")).toHaveTextContent("Opening Contoso SOC.");
    for (const option of within(group).getAllByRole("option")) expect(option).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(within(group).getByRole("option", { name: "Switch to Fabrikam" }));
    await waitFor(() => { expect(held.answer).toBeDefined(); });
    expect(posts(calls)).toHaveLength(1);
    expect(posts(calls)[0]).toMatchObject({ body: { tenant_id: tenant(2), section: "/activity" } });
  });

  it("still land the person when the palette closes before the answer", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { pathname: "/board", assign });
    const held: { answer?: (response: Response) => void } = {};
    const { view } = provide(THREE, { [SWITCH]: () => new Promise<Response>((resolve) => { held.answer = resolve; }) });
    const group = await screen.findByRole("group", { name: "Workspaces" });
    await userEvent.click(within(group).getByRole("option", { name: "Switch to Fabrikam" }));
    await waitFor(() => { expect(held.answer).toBeDefined(); });
    view.unmount();
    held.answer?.(json({ location: "/board" }));
    await waitFor(() => { expect(assign).toHaveBeenCalledWith("/board"); });
  });

  it("show the client's own sentence when the switch is refused", async () => {
    provide(THREE, { [SWITCH]: () => json({ code: "DIRECTORY_REQUIRED" }, 403) });
    const group = await screen.findByRole("group", { name: "Workspaces" });
    await userEvent.click(within(group).getByRole("option", { name: "Switch to Fabrikam" }));
    expect(await within(group).findByRole("alert")).toHaveTextContent("organization sign-in");
  });
});
