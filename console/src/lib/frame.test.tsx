// SPDX-License-Identifier: AGPL-3.0-only
// The plain frame stays until the session is known, and whatever renders first removes it
// (NV19, #678): the session, a failed read said in the frame's own styling, the route boundary
// when the shell itself throws, and the not-found page.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { NotFound } from "../components/NotFound";
import { RouteError } from "../components/RouteError";
import { answerWith, heldReply, UNAVAILABLE } from "../test/page";
import { removeFrame } from "./frame";
import { SessionProvider } from "./SessionProvider";
import { invalidateWorkspace, resetWorkspace } from "./workspace-context";

function paintFrame(): void {
  const frame = document.createElement("div");
  frame.id = "frame";
  frame.className = "frame";
  const main = document.createElement("main");
  main.className = "frame-main";
  const status = document.createElement("p");
  status.className = "frame-status";
  status.setAttribute("role", "status");
  status.textContent = "Loading";
  main.append(status);
  frame.append(main);
  document.body.prepend(frame);
}

const VIEW = {
  generation: "g-1",
  can_switch_workspaces: false,
  identity: { principal_id: "p-1", kind: "ADMIN", label: "Person" },
  tenant: { tenant_id: "t-1", name: "Acme", mode: "ENFORCE", approval_deadline_seconds: 900 },
  access: { managed: false, roles: ["administrator"], permissions: ["console.read"], workspace_permissions: [], space_permissions: {} },
  space: null,
  spaces: 1,
  all_spaces: false,
  csrf_token: "csrf",
  release: null,
  expires_at: "2026-09-19T20:00:00Z",
  stop: null,
  assistant: false,
  invitations: false,
  mail: true,
  features: [],
};

function provide() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SessionProvider>
        <h1>The console</h1>
      </SessionProvider>
    </QueryClientProvider>,
  );
}

const frame = () => document.getElementById("frame");

beforeEach(() => {
  paintFrame();
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  frame()?.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  resetWorkspace();
});

describe("the plain frame (NV19, #678)", () => {
  it("is removed once, and a second removal does nothing", () => {
    removeFrame();
    expect(frame()).toBeNull();
    expect(() => {
      removeFrame();
    }).not.toThrow();
  });

  it("stays while the session is read, and goes when it arrives", async () => {
    const held = heldReply();
    answerWith({ "GET /api/console/v1/session": () => held.reply });
    provide();
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(frame()).not.toBeNull();
    expect(screen.queryByRole("heading")).toBeNull();
    held.send({ body: VIEW });
    expect(await screen.findByRole("heading", { name: "The console" })).toBeInTheDocument();
    expect(frame()).toBeNull();
  });

  it("says a failed read in the frame's own styling, and reads again on Try again", async () => {
    let reads = 0;
    answerWith({ "GET /api/console/v1/session": () => (++reads === 1 ? UNAVAILABLE : { body: VIEW }) });
    provide();
    const heading = await screen.findByRole("heading", { name: "Your session could not be loaded." });
    expect(frame()).toBeNull();
    expect(heading.closest(".frame")).not.toBeNull();
    const again = screen.getByRole("button", { name: "Try again" });
    expect(again).toHaveClass("btn");
    await userEvent.click(again);
    expect(await screen.findByRole("heading", { name: "The console" })).toBeInTheDocument();
    expect(reads).toBe(2);
  });

  it("goes when the workspace changed under the tab", async () => {
    answerWith({ "GET /api/console/v1/session": { body: VIEW } });
    act(() => {
      invalidateWorkspace();
    });
    provide();
    expect(await screen.findByRole("heading", { name: "Workspace changed" })).toBeInTheDocument();
    expect(frame()).toBeNull();
  });

  it("goes when the shell itself throws, and the error card shows", async () => {
    const root = createRootRoute({
      component: () => {
        throw new Error("the shell failed while rendering");
      },
    });
    const router = createRouter({
      routeTree: root,
      history: createMemoryHistory({ initialEntries: ["/"] }),
      defaultErrorComponent: RouteError,
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { level: 1, name: "This page could not load" })).toBeVisible();
    expect(frame()).toBeNull();
  });

  it("goes for a page that does not exist", async () => {
    const root = createRootRoute();
    const home = createRoute({ getParentRoute: () => root, path: "/", component: () => null });
    const router = createRouter({
      routeTree: root.addChildren([home]),
      history: createMemoryHistory({ initialEntries: ["/nowhere"] }),
      defaultNotFoundComponent: NotFound,
    });
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { level: 1, name: "There is no page here" })).toBeInTheDocument();
    await waitFor(() => {
      expect(frame()).toBeNull();
    });
  });
});
