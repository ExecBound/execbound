// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceItem } from "../api/types.gen";
import { SignOut } from "../shell/SignOut";
import { json, serve } from "../test/api";
import { PLACEHOLDER, SessionContext } from "./session";
import { ordered, readRecent, rememberRecent } from "./workspace-recents";
import { clearRecentWorkspaces } from "./workspaces";
import { useWorkspaceSwitch } from "./workspace-switch";
import { resetWorkspace } from "./workspace-context";

const KEY = "eb.recent.v1.workspaces";
const IDS = Array.from({ length: 12 }, (_, n) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`);
const item = (tenant: string, name: string, current = false, entered: string | null = null): WorkspaceItem => ({
  tenant_id: tenant, name, current, kind: "HUMAN_APPROVER", roles: ["viewer"], entry: "open",
  waiting_state: current ? "current" : "counted", waiting: current ? null : 0, next_lapse: null,
  last_entered_at: entered,
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  resetWorkspace();
  window.localStorage.clear();
  window.history.replaceState(null, "", "/");
});

describe("the order the menu shows", () => {
  const list = [item(IDS[0] ?? "", "A"), item(IDS[1] ?? "", "B", true), item(IDS[2] ?? "", "C"), item(IDS[3] ?? "", "D")];

  it("is the current workspace, then this browser's recent ones, then the server's order", () => {
    expect(ordered(list, [IDS[3] ?? "", IDS[2] ?? ""]).map((w) => w.name)).toEqual(["B", "D", "C", "A"]);
    expect(ordered(list, []).map((w) => w.name)).toEqual(["B", "A", "C", "D"]);
  });

  it("puts what the account entered last before this browser's recent ones", () => {
    const entered = [
      item(IDS[0] ?? "", "A", false, "2026-10-11T09:00:00Z"),
      item(IDS[1] ?? "", "B", true, "2026-10-11T11:00:00Z"),
      item(IDS[2] ?? "", "C"),
      item(IDS[3] ?? "", "D", false, "2026-10-11T10:00:00Z"),
      item(IDS[4] ?? "", "E"),
    ];
    // B is current; D then A by when the account entered them, wherever that was; then C and E,
    // never entered, by this browser's recent order and then the server's.
    expect(ordered(entered, [IDS[4] ?? "", IDS[0] ?? ""]).map((w) => w.name)).toEqual(["B", "D", "A", "E", "C"]);
    expect(ordered(entered, []).map((w) => w.name)).toEqual(["B", "D", "A", "C", "E"]);
  });

  it("orders nothing the server did not list", () => {
    expect(ordered(list, [IDS[9] ?? ""]).map((w) => w.name)).toEqual(["B", "A", "C", "D"]);
  });

  it("keeps the server's order when the store throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    expect(() => { rememberRecent(IDS[2]); }).not.toThrow();
    expect(readRecent()).toEqual([]);
    expect(ordered(list, readRecent()).map((w) => w.name)).toEqual(["B", "A", "C", "D"]);
  });

  it("ignores a malformed store and anything that is not a tenant id", () => {
    window.localStorage.setItem(KEY, "{not json");
    expect(readRecent()).toEqual([]);
    window.localStorage.setItem(KEY, JSON.stringify([IDS[2], "javascript:alert(1)", 7, IDS[3]]));
    expect(readRecent()).toEqual([IDS[2], IDS[3]]);
    window.localStorage.setItem(KEY, JSON.stringify({ ids: [IDS[2]] }));
    expect(readRecent()).toEqual([]);
  });

  it("keeps ten workspaces at most, the latest first", () => {
    for (const tenant of IDS.slice(0, 11)) rememberRecent(tenant);
    expect(readRecent()).toEqual(IDS.slice(1, 11).reverse());
  });
});

describe("forgetting the recent workspaces", () => {
  it("clears the store", () => {
    rememberRecent(IDS[2]);
    clearRecentWorkspaces();
    expect(window.localStorage.getItem(KEY)).toBeNull();
  });

  it("happens on sign-out, beside the drafts, before the browser posts", async () => {
    rememberRecent(IDS[2]);
    const drafts = await import("./drafts");
    const cleared = vi.spyOn(drafts, "clearDrafts");
    const submit = vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(() => undefined);
    render(<SessionContext.Provider value={{ ...PLACEHOLDER, csrf: "token" }}><SignOut /></SessionContext.Provider>);
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => { expect(submit).toHaveBeenCalled(); });
    expect(cleared).toHaveBeenCalled();
    expect(window.localStorage.getItem(KEY)).toBeNull();
  });
});

describe("switching", () => {
  const A = "aaaaaaaa-0000-4000-8000-00000000000a";
  const B = "bbbbbbbb-0000-4000-8000-00000000000b";
  const POLICY = "abcdef01-0000-4000-8000-000000000001";

  function Switch({ onReady }: { onReady: (run: (to: { id: string; name: string }) => void) => void }) {
    const switcher = useWorkspaceSwitch();
    useEffect(() => { onReady((to) => { switcher.mutate(to); }); });
    return null;
  }

  function mount(client: QueryClient, onReady: (run: (to: { id: string; name: string }) => void) => void) {
    return render(
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={{ ...PLACEHOLDER, canSwitchWorkspaces: true, tenant: { id: A, name: "Personal", detail: "" } }}>
          <Switch onReady={onReady} />
        </SessionContext.Provider>
      </QueryClientProvider>,
    );
  }

  it.each([
    [`/policy/${POLICY}`, { section: "/policy" }],
    [`/workspaces/${A}/approvals/${POLICY}`, { section: "/approvals" }],
    ["/invitations", { section: "/" }],
    ["/ask", {}],
  ])("sends the section of %s and never a record", async (path, extra) => {
    window.history.replaceState(null, "", path);
    const assign = vi.fn();
    vi.stubGlobal("location", { pathname: path, assign });
    const calls = serve({ "/api/console/v1/session/workspace": { location: "/policy" } });
    let run: (to: { id: string; name: string }) => void = () => undefined;
    mount(new QueryClient(), (go) => { run = go; });
    act(() => { run({ id: B, name: "Team" }); });
    await waitFor(() => { expect(assign).toHaveBeenCalledWith("/policy"); });
    expect(calls.find((call) => call.method === "POST")?.body).toEqual({ tenant_id: B, ...extra });
  });

  it("lands on the answer even when the one who asked has gone, and remembers both workspaces", async () => {
    window.history.replaceState(null, "", "/board");
    const assign = vi.fn();
    vi.stubGlobal("location", { pathname: "/board", assign });
    const held: { answer?: (response: Response) => void } = {};
    serve({ "/api/console/v1/session/workspace": () => new Promise<Response>((resolve) => { held.answer = resolve; }) });
    let run: (to: { id: string; name: string }) => void = () => undefined;
    const client = new QueryClient();
    const view = mount(client, (go) => { run = go; });
    act(() => { run({ id: B, name: "Team" }); });
    await waitFor(() => { expect(held.answer).toBeDefined(); });
    view.unmount();
    held.answer?.(json({ location: "/board" }));
    await waitFor(() => { expect(assign).toHaveBeenCalledWith("/board"); });
    expect(readRecent()).toEqual([B, A]);
  });
});
