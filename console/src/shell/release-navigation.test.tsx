// SPDX-License-Identifier: AGPL-3.0-only
// A newer release loads on the next change of page, never while a change is being sent (NV18,
// #678): a query change stays in the page, Reload waits for the change in flight and asks once
// over an open dialog, and an idle Live board reloads itself.

import { QueryClient, QueryClientProvider, useMutation } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, Outlet, RouterProvider, useRouter } from "@tanstack/react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PageHeading } from "../components/ui/PageHeading";
import { forgetRelease, noteRelease, RELEASE_HEADER, RELEASE_META } from "../lib/release";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";
import { serve } from "../test/api";
import { BOARD_IDLE_MS } from "./release-navigation";
import { Shell } from "./Shell";

const admin: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", permissions: ["console.read", "workspace.manage"], csrf: "token" };

let release: () => void = () => undefined;

/** A page that sends one change the test holds open, and changes its own query. */
function Sending() {
  const { history } = useRouter();
  const send = useMutation({
    mutationFn: () =>
      new Promise<void>((done) => {
        release = done;
      }),
  });
  return (
    <>
      <PageHeading title="Home" />
      <button type="button" onClick={() => { send.mutate(); }}>Send a decision</button>
      <button type="button" onClick={() => { history.push("/?state=held"); }}>Held</button>
    </>
  );
}

function mount(initial = "/") {
  serve({});
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const root = createRootRoute({
    component: () => (
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={admin}>
          <Shell>
            <Outlet />
          </Shell>
        </SessionContext.Provider>
      </QueryClientProvider>
    ),
  });
  const pages = [
    createRoute({ getParentRoute: () => root, path: "/", component: Sending }),
    createRoute({ getParentRoute: () => root, path: "/activity", component: () => <PageHeading title="Activity" /> }),
    createRoute({ getParentRoute: () => root, path: "/board", component: () => <PageHeading title="Live board" /> }),
  ];
  const router = createRouter({ routeTree: root.addChildren(pages), history: createMemoryHistory({ initialEntries: [initial] }) });
  render(<RouterProvider router={router} />);
  return router;
}

let meta: HTMLMetaElement;
let assign: ReturnType<typeof vi.fn>;
let reload: ReturnType<typeof vi.fn>;

/** Notes a newer release once the shell's after-paint layer, which acts on it, is in place. */
async function newer() {
  await waitFor(() => {
    expect(document.querySelector("[data-announcer]")).not.toBeNull();
  });
  act(() => {
    noteRelease(new Headers({ [RELEASE_HEADER]: "served-2222" }));
  });
}

async function banner(): Promise<HTMLElement> {
  const sentence = await screen.findByText("A new version of ExecBound is available. It loads when you next change page.");
  const found = sentence.closest<HTMLElement>('[role="status"]');
  if (found === null) throw new Error("no banner");
  return found;
}

beforeEach(() => {
  meta = document.createElement("meta");
  meta.setAttribute("name", RELEASE_META);
  meta.setAttribute("content", "built-1111");
  document.head.append(meta);
  assign = vi.fn();
  reload = vi.fn();
  vi.stubGlobal("location", { assign, reload, origin: window.location.origin, href: window.location.href });
});

afterEach(() => {
  meta.remove();
  forgetRelease();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  document.body.querySelectorAll("[data-test-dialog]").forEach((node) => {
    node.remove();
  });
});

async function goToActivity() {
  const sidebar = await screen.findByRole("navigation", { name: "Main" });
  await userEvent.click(within(sidebar).getByRole("link", { name: "Activity" }));
}

describe("loading a newer release (NV18, #678)", () => {
  it("does nothing while no newer release is noted", async () => {
    const router = mount();
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await goToActivity();
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(assign).not.toHaveBeenCalled();
  });

  it("makes the next change of page a document navigation, and leaves a query change in the page", async () => {
    const router = mount();
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await newer();
    await banner();
    await userEvent.click(screen.getByRole("button", { name: "Held" }));
    await waitFor(() => {
      expect(router.state.location.search).toEqual({ state: "held" });
    });
    expect(assign).not.toHaveBeenCalled();
    await goToActivity();
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/activity");
    });
    expect(router.state.location.pathname).toBe("/");
  });

  it("never reloads while a change is being sent, and holds Reload until it is done", async () => {
    const router = mount();
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await newer();
    const shown = await banner();
    await userEvent.click(screen.getByRole("button", { name: "Send a decision" }));
    await waitFor(() => {
      expect(within(shown).getByRole("button", { name: "Reload" })).toBeDisabled();
    });
    expect(within(shown).getByText("Reload when the change being sent has finished.")).toBeInTheDocument();
    await goToActivity();
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/activity");
    });
    expect(assign).not.toHaveBeenCalled();
    await act(async () => {
      release();
      await Promise.resolve();
    });
    await waitFor(() => {
      expect(within(shown).getByRole("button", { name: "Reload" })).toBeEnabled();
    });
    const sidebar = screen.getByRole("navigation", { name: "Main" });
    await userEvent.click(within(sidebar).getByRole("link", { name: "Home" }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/");
    });
  });

  it("asks once before reloading over an open dialog, and reloads at once without one", async () => {
    mount();
    await screen.findByRole("heading", { level: 1, name: "Home" });
    await newer();
    const shown = await banner();
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("data-test-dialog", "");
    document.body.append(dialog);
    await userEvent.click(within(shown).getByRole("button", { name: "Reload" }));
    expect(reload).not.toHaveBeenCalled();
    expect(within(shown).getByRole("button", { name: "Reload and lose what is typed" })).toBeInTheDocument();
    await userEvent.click(within(shown).getByRole("button", { name: "Not now" }));
    expect(within(shown).getByRole("button", { name: "Reload" })).toBeInTheDocument();
    await userEvent.click(within(shown).getByRole("button", { name: "Reload" }));
    await userEvent.click(within(shown).getByRole("button", { name: "Reload and lose what is typed" }));
    expect(reload).toHaveBeenCalledTimes(1);
    dialog.remove();
    await userEvent.click(within(shown).getByRole("button", { name: /^Reload/ }));
    expect(reload).toHaveBeenCalledTimes(2);
  });
});

describe("the Live board on a wall (NV18, #678)", () => {
  it("reloads after a minute with no input, starting again on a key", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mount("/board");
    await screen.findByRole("heading", { level: 1, name: "Live board" });
    await newer();
    await banner();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BOARD_IDLE_MS - 1000);
    });
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "Shift" }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BOARD_IDLE_MS - 1000);
    });
    expect(reload).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("does not reload over an open dialog", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mount("/board");
    await screen.findByRole("heading", { level: 1, name: "Live board" });
    await newer();
    await banner();
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("data-test-dialog", "");
    document.body.append(dialog);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(BOARD_IDLE_MS + 1000);
    });
    expect(reload).not.toHaveBeenCalled();
  });
});
