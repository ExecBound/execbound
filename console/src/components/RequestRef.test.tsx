// SPDX-License-Identifier: AGPL-3.0-only
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import type { WorkspaceItem } from "../api/types.gen";
import { PLACEHOLDER, SessionContext } from "../lib/session";
import { serve } from "../test/api";
import { RequestRef } from "./RequestRef";

const tenant = (n: number) => `${String(n).padStart(8, "0")}-0000-4000-8000-000000000000`;
const item = (n: number, name: string, current = false): WorkspaceItem => ({
  tenant_id: tenant(n), name, current, kind: "HUMAN_APPROVER", roles: ["viewer"], entry: "open",
  waiting_state: current ? "current" : "counted", waiting: current ? null : 0, next_lapse: null, last_entered_at: null,
});

afterEach(() => { vi.unstubAllGlobals(); });

function show(workspaces: WorkspaceItem[], canSwitch = true) {
  const calls = serve({ "/api/console/v1/session/workspaces": { workspaces } });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SessionContext.Provider value={{ ...PLACEHOLDER, canSwitchWorkspaces: canSwitch, tenant: { id: tenant(1), name: "Team <script>", detail: "" } }}>
        <p data-testid="ref"><RequestRef value="EB-12" /></p>
        <p data-testid="drawer"><RequestRef prefix="Request " value="EB-12" /></p>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
  return calls;
}

it("is the reference alone for a person with one workspace", async () => {
  const calls = show([item(1, "Team <script>", true)]);
  await waitFor(() => { expect(calls.length).toBe(1); });
  expect(screen.getByTestId("ref")).toHaveTextContent(/^EB-12$/);
});

it("is the reference alone where the session cannot switch workspaces, and asks for no list", () => {
  const calls = show([item(1, "Team <script>", true), item(2, "Other")], false);
  expect(screen.getByTestId("ref")).toHaveTextContent(/^EB-12$/);
  expect(screen.getByText("Request EB-12")).toBeInTheDocument();
  expect(calls).toHaveLength(0);
});

it("names the workspace, as text, for a person with several", async () => {
  show([item(1, "Team <script>", true), item(2, "Other")]);
  await waitFor(() => { expect(screen.getByTestId("ref")).toHaveTextContent("EB-12 · Team <script>"); });
  expect(screen.getByTestId("drawer")).toHaveTextContent(/^Request EB-12 · Team <script>$/);
  expect(screen.getByTestId("ref").querySelector("script")).toBeNull();
});
