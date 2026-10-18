// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { json, serve } from "../test/api";
import { createClientConfig } from "./client-config";
import { SessionProvider } from "./SessionProvider";
import { installConfirm, receive, resetWorkspace } from "./workspace-context";

afterEach(() => { vi.unstubAllGlobals(); resetWorkspace(); window.history.replaceState(null, "", "/"); });

const A = "abcdef01-0000-4000-8000-000000000001";
const B = "abcdef01-0000-4000-8000-000000000002";
const G1 = "11111111-0000-4000-8000-000000000001";
const G2 = "22222222-0000-4000-8000-000000000002";

function view(generation: string, tenant: string, name: string) {
  return {
    generation, can_switch_workspaces: true,
    identity: { principal_id: A, kind: "ADMIN", label: "Person" },
    tenant: { tenant_id: tenant, name, mode: "ENFORCE" },
    access: { managed: false, roles: ["administrator"], permissions: [], space_permissions: {} },
    space: null, spaces: 1, all_spaces: true, csrf_token: "csrf", stop: null,
    assistant: false, invitations: false, mail: true, features: [],
  };
}

function provide(client = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  const mounted = vi.fn();
  function Page() { mounted(); return <p>Data from the workspace</p>; }
  render(<QueryClientProvider client={client}><SessionProvider><Page /></SessionProvider></QueryClientProvider>);
  return mounted;
}

it("never mounts an approval under a different bootstrap workspace, even when its id collides", async () => {
  const path = `/workspaces/${B}/approvals/${A}`;
  window.history.replaceState(null, "", path);
  serve({ "/api/console/v1/session": view(A, A, "Wrong workspace") });
  const mounted = provide();
  expect(await screen.findByRole("link", { name: "Open review workspace" })).toHaveAttribute("href", path);
  // It says where the browser is, and does not name the workspace the link belongs to.
  expect(screen.getByText(/You are in Wrong workspace\. This request belongs to another workspace\./)).toBeInTheDocument();
  expect(mounted).not.toHaveBeenCalled();
  expect(screen.queryByText("Data from the workspace")).not.toBeInTheDocument();
});

describe("a tab left behind", () => {
  it("names the workspace it showed and the one the browser is in, and links to its section", async () => {
    window.history.replaceState(null, "", `/policy/${A}`);
    serve({ "/api/console/v1/session": view(G1, A, "Personal") });
    provide();
    await screen.findByText("Data from the workspace");
    await act(() => receive({ v: 1, kind: "switching", tenant_id: B, name: "Team <script>" }));
    const heading = await screen.findByRole("heading", { name: "Workspace changed" });
    expect(screen.getByText("This tab was showing Personal. This browser is now in Team <script>.")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: "Open Policies in Team <script>" });
    expect(link).toHaveAttribute("href", "/policy");
    expect(heading).toHaveFocus();
    expect(screen.queryByText("Data from the workspace")).not.toBeInTheDocument();
  });

  it("offers to reload its own page after a sign-in again to the same workspace", async () => {
    window.history.replaceState(null, "", `/policy/${A}?tab=rules`);
    serve({ "/api/console/v1/session": view(G1, A, "Personal") });
    provide();
    await screen.findByText("Data from the workspace");
    installConfirm(() => Promise.resolve(G2));
    await act(() => receive({ v: 1, kind: "entered", generation: G2, tenant_id: A, name: "Personal" }));
    const heading = await screen.findByRole("heading", { name: "You signed in again" });
    expect(screen.getByText(/This tab belongs to an earlier sign-in to Personal\./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Reload this page" })).toHaveAttribute("href", `/policy/${A}?tab=rules`);
    expect(heading).toHaveFocus();
  });

  it("knows nothing more when only a response said the session changed", async () => {
    window.history.replaceState(null, "", "/board");
    let reads = 0;
    serve({
      "/api/console/v1/session": () => {
        reads += 1;
        return reads === 1 ? json(view(G1, A, "Personal")) : new Response("{}", { headers: { "X-ExecBound-Workspace": G2 } });
      },
      "/api/console/v1/other": () => new Response("{}", { headers: { "X-ExecBound-Workspace": G2 } }),
    });
    provide();
    await screen.findByText("Data from the workspace");
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    await act(async () => {
      await run(new Request("/api/console/v1/other")).catch(() => undefined);
    });
    expect(await screen.findByRole("heading", { name: "Workspace changed" })).toBeInTheDocument();
    expect(screen.getByText("This tab was showing Personal. This browser has since moved to another workspace or signed in again.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Live board" })).toHaveAttribute("href", "/board");
  });
});

describe("the workspace list", () => {
  it("is read again with each session refetch, and not with the first read", async () => {
    serve({ "/api/console/v1/session": view(G1, A, "Personal") });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidate = vi.spyOn(client, "invalidateQueries");
    provide(client);
    await screen.findByText("Data from the workspace");
    expect(invalidate).not.toHaveBeenCalled();
    await act(() => client.refetchQueries({ queryKey: [{ _id: "readSession" }] }));
    await waitFor(() => {
      expect(invalidate).toHaveBeenCalledWith(
        expect.objectContaining({ queryKey: [expect.objectContaining({ _id: "readWorkspaces" })], refetchType: "active" }),
        { cancelRefetch: false },
      );
    });
  });
});
