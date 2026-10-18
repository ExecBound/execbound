// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";

import { PLACEHOLDER } from "../../lib/session";
import { answerWith, renderPage } from "../../test/page";
import { NewAgent } from "./AgentsList";

const FIRST = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECOND = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const AGENT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const spaces = {
  items: [
    { space_id: FIRST, name: "Security", archived_at: null },
    { space_id: SECOND, name: "Engineering", archived_at: null },
  ], next_cursor: null, administrator: true, current_space_id: null, all_spaces: true,
};

afterEach(() => { vi.unstubAllGlobals(); localStorage.clear(); });

it("requires a supported host and explicit Space, then selects that Space before creating", async () => {
  const calls = answerWith({
    "GET /api/console/v1/spaces": { body: spaces },
    "POST /api/console/v1/session/space": { body: { space: { space_id: SECOND, name: "Engineering", archived: false } } },
    "POST /api/console/v1/agents": { body: { principal_id: AGENT } },
  });
  renderPage(<NewAgent />, { ...PLACEHOLDER, role: "ADMIN", spaces: 2, allSpaces: true });
  await userEvent.click(await screen.findByRole("button", { name: "Add agent" }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByRole("button", { name: "Continue" })).toBeDisabled();
  await userEvent.selectOptions(within(dialog).getByLabelText("Agent host"), "cursor.json");
  await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  await userEvent.type(within(dialog).getByLabelText("Agent name"), "Build helper");
  expect(within(dialog).getByRole("button", { name: "Create agent and connect" })).toBeDisabled();
  await userEvent.selectOptions(await within(dialog).findByLabelText("Space"), SECOND);
  await userEvent.click(within(dialog).getByRole("button", { name: "Create agent and connect" }));
  await waitFor(() => { expect(calls.filter((call) => call.method === "POST")).toHaveLength(2); });
  expect(calls.filter((call) => call.method === "POST").map(({ path, body }) => ({ path, body }))).toEqual([
    { path: "/api/console/v1/session/space", body: { space_id: SECOND } },
    { path: "/api/console/v1/agents", body: { label: "Build helper" } },
  ]);
  expect(localStorage.getItem(`execbound.agent-host.${AGENT}`)).toBe("cursor.json");
});

it("keeps the name and selected host when the server refuses the Space, without creating an agent", async () => {
  const calls = answerWith({
    "GET /api/console/v1/spaces": { body: spaces },
    "POST /api/console/v1/session/space": { status: 404, body: { code: "NOT_FOUND", detail: "That Space is no longer available." } },
    "POST /api/console/v1/agents": { body: { principal_id: AGENT } },
  });
  renderPage(<NewAgent />, { ...PLACEHOLDER, role: "ADMIN", spaces: 2, allSpaces: true });
  await userEvent.click(await screen.findByRole("button", { name: "Add agent" }));
  const dialog = await screen.findByRole("dialog");
  await userEvent.selectOptions(within(dialog).getByLabelText("Agent host"), "mcp");
  await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  await userEvent.type(within(dialog).getByLabelText("Agent name"), "SOC helper");
  await userEvent.selectOptions(await within(dialog).findByLabelText("Space"), SECOND);
  await userEvent.click(within(dialog).getByRole("button", { name: "Create agent and connect" }));
  await waitFor(() => { expect(within(dialog).getByRole("alert")).toBeInTheDocument(); });
  expect(within(dialog).getByLabelText("Agent name")).toHaveValue("SOC helper");
  expect(calls.some((call) => call.method === "POST" && call.path.endsWith("/agents"))).toBe(false);
  await userEvent.click(within(dialog).getByRole("button", { name: "Back" }));
  expect(within(dialog).getByLabelText("Agent host")).toHaveValue("mcp");
});
