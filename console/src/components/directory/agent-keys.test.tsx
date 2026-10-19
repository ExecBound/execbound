// SPDX-License-Identifier: AGPL-3.0-only
// Agent keys (#678): a lifetime is chosen, never preselected (AK1); the key tables read expiry
// and last use relative to the server's clock and say when a key is replaced; Rotate issues a
// key naming the one it replaces and shows it once (AK6); an expiring key's notice names the
// agent as text and links to its page (AK5).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

import type { AgentDetail, CredentialRow, ExpiringKey } from "../../api/types.gen";
import { forgetServerTime } from "../../lib/clock";
import { json, serve } from "../../test/api";
import { AgentDetailView } from "./AgentDetail";
import { KeyNotice } from "./KeyNotice";
import { PersonalTokens } from "../settings/PersonalTokens";

const AGENT = "22222222-2222-2222-2222-222222222222";
const KEY = "66666666-6666-6666-6666-666666666666";
const OLD = "77777777-7777-7777-7777-777777777777";
const SPARE = "88888888-8888-8888-8888-888888888888";
const NEW = "99999999-9999-9999-9999-999999999999";
const DISCOVERED = "44444444-4444-4444-4444-444444444444";
// What the issue route answers; shaped like no real key, so no scanner mistakes it for one.
const TOKEN = "shown-once-rotated-key-for-the-test";
const HOSTILE = "<img src=x onerror=alert(1)>";
// The server's clock in every test here: 2026-10-08 12:00 UTC.
const NOW = Date.UTC(2026, 9, 8, 12, 0, 0);

function key(overrides: Partial<CredentialRow>): CredentialRow {
  return {
    credential_id: KEY,
    number: 2,
    issued_at: "2026-10-01T08:00:00Z",
    expires_at: "2026-10-08T18:00:00Z",
    revoked_at: null,
    state: "live",
    failures: 0,
    last_used_at: "2026-10-08T11:55:00Z",
    replaced: false,
    ...overrides,
  };
}

const GOVERNED: AgentDetail = {
  row_id: AGENT,
  kind: "principal",
  agent: { principal_id: AGENT, active: true, dormant: false, label: HOSTILE, number: 3, created_at: "2026-09-10T08:00:00Z", deactivated_at: null },
  binding: null,
  discovered: null,
  credentials: [
    key({}),
    key({ credential_id: OLD, number: 1, expires_at: "2026-11-30T00:00:00Z", last_used_at: null, replaced: true }),
    key({ credential_id: SPARE, number: 4, expires_at: "9999-12-31T00:00:00Z", last_used_at: "2026-10-06T12:00:00Z" }),
  ],
  recent: [],
  runs: [],
  more_runs: false,
  groups: [],
  requests: 0,
  month: "2026-10-01T00:00:00Z",
  bundle: true,
  observe: false,
  limits: [],
  reach: [],
  rules_bundle_id: null,
  options: [],
};

const NOTICE: ExpiringKey = {
  credential_id: KEY,
  number: 2,
  principal_id: AGENT,
  principal_number: 3,
  principal_label: HOSTILE,
  expires_at: "2026-10-09T08:00:00Z",
  last_used_at: "2026-10-08T11:55:00Z",
};

function mount(element: ReactNode, initial = `/agents/${AGENT}`, queryClient = new QueryClient()) {
  const rootRoute = createRootRoute({ component: () => <Outlet /> });
  const page = (path: string, node: ReactNode) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: () => node });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      page("/agents/$agentId", element),
      page("/settings", element),
      page("/credentials", <p>Keys</p>),
      page("/activity", <p>Activity</p>),
      page("/policy", <p>Policy</p>),
      page("/monitor", <p>Monitoring</p>),
    ]),
    history: createMemoryHistory({ initialEntries: [initial] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { router, queryClient };
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  forgetServerTime();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  localStorage.clear();
});

/** The API keys card, in the Connection section a new agent opens on. */
async function openKeys() {
  const card = (await screen.findByRole("heading", { level: 2, name: "API keys" })).closest("section");
  if (card === null) throw new Error("No API keys card");
  return card;
}

describe("choosing a key's lifetime (AK1)", () => {
  it("starts every agent key form at Choose a lifetime and sends only a chosen value", async () => {
    const calls = serve({
      [`/api/console/v1/agents/${AGENT}/credentials/issue`]: { token: TOKEN, credential_id: NEW, principal_id: AGENT, kind: "AGENT", expires_at: "2026-11-07T12:00:00Z", number: 5 },
    });
    mount(<AgentDetailView detail={GOVERNED} />);
    // Connect this agent's step 1, then the API keys card.
    const connect = await screen.findByLabelText("API key expires after");
    expect(connect).toHaveValue("");
    expect(within(connect).getByRole("option", { name: "Choose a lifetime" })).toBeDisabled();
    expect(connect).toHaveAccessibleDescription(/usually needs 30 or 90 days. Rotate the key before it expires./);
    expect(screen.getByRole("button", { name: "Issue another API key" })).toBeDisabled();
    const card = await openKeys();
    const lifetime = within(card).getByLabelText("Issue an API key with a lifetime of");
    expect(lifetime).toHaveValue("");
    const submit = within(card).getByRole("button", { name: "Issue API key" });
    expect(submit).toBeDisabled();
    await userEvent.selectOptions(lifetime, "2160");
    expect(submit).toBeEnabled();
    await userEvent.click(submit);
    await screen.findByRole("dialog", { name: "Copy the API key now" });
    const issued = calls.find((call) => call.path.endsWith("/credentials/issue"));
    expect(issued?.body).toEqual({ lifetime: "2160" });
  });

  it("starts Govern this agent at Choose a lifetime", async () => {
    serve({});
    const discovered: AgentDetail = {
      ...GOVERNED,
      row_id: DISCOVERED,
      kind: "discovered",
      agent: null,
      credentials: [],
      discovered: {
        agent: {
          agent_id: DISCOVERED, platform_ref: "sp-1", identity_class: "agent_identity", class_label: "agent identity",
          source_label: "Entra", display_name: "Synthetic", enabled: true, blueprint_ref: null, credential_kinds: [],
          sponsors: [], sponsor_state: "read", first_seen_at: "2026-10-01T00:00:00Z", observed_at: "2026-10-08T00:00:00Z", gone_at: null,
          synthetic: false,
        },
        findings: [],
        observations: [],
      },
    };
    mount(<AgentDetailView detail={discovered} />, `/agents/${DISCOVERED}`);
    const govern = await screen.findByRole("button", { name: "Govern this agent" });
    expect(govern).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText(/Govern this agent: create its principal/), "720");
    expect(govern).toBeEnabled();
  });

  it("keeps a personal access token's 30-day default", async () => {
    serve({ "/api/console/v1/settings/tokens": { tokens: [], limit: 10, live: 0 } });
    mount(<PersonalTokens />, "/settings");
    await userEvent.click(await screen.findByRole("button", { name: "Create token" }));
    expect(await screen.findByLabelText("Lifetime")).toHaveValue("720");
  });
});

describe("the agent page's key table", () => {
  it("reads expiry and last use relative to the server's clock, marks the soon and the replaced", async () => {
    serve({});
    mount(<AgentDetailView detail={GOVERNED} />);
    const card = await openKeys();
    const rows = within(within(card).getByRole("table")).getAllByRole("row");
    expect(within(rows[0] ?? card).getByRole("columnheader", { name: "Last used" })).toBeInTheDocument();
    // Key 2: expires in six hours, last used five minutes ago, live, expires soon.
    expect(rows[1]).toHaveTextContent("in 6 h");
    expect(within(rows[1] ?? card).getByText("Expires soon")).toHaveClass("badge-hold");
    expect(rows[1]).toHaveTextContent("5 min ago");
    // Key 1: replaced by a newer key, never used, not soon.
    expect(rows[2]).toHaveTextContent("live, replaced by a newer key");
    expect(rows[2]).toHaveTextContent("Never used");
    expect(within(rows[2] ?? card).queryByText("Expires soon")).toBeNull();
    // Key 4: never expires.
    expect(rows[3]).toHaveTextContent("Never");
    expect(within(rows[3] ?? card).queryByText("Expires soon")).toBeNull();
    expect(within(card).getByRole("button", { name: "Rotate key 2" })).toBeInTheDocument();
  });

  it("shows the agent's notice, naming a hostile label as text", async () => {
    serve({});
    mount(<AgentDetailView detail={{ ...GOVERNED, expiring_key: NOTICE }} section="overview" />);
    const link = await screen.findByRole("link", { name: `Key 2 for ${HOSTILE}` });
    expect(link).toHaveAttribute("href", `/agents/${AGENT}?section=connection`);
    expect(link.closest("p")).toHaveTextContent(
      `Key 2 for ${HOSTILE} expires in 20 h. It was last used 5 min ago. Rotate it, update the tool that uses it, then revoke the old key.`,
    );
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("rotating a key (AK6)", () => {
  it("issues a key naming the old one, shows it once with where it goes, and keeps it nowhere", async () => {
    const calls = serve({
      [`/api/console/v1/agents/${AGENT}/credentials/issue`]: { token: TOKEN, credential_id: NEW, principal_id: AGENT, kind: "AGENT", expires_at: "2027-01-06T12:00:00Z", number: 5 },
    });
    const queryClient = new QueryClient();
    mount(<AgentDetailView detail={GOVERNED} />, `/agents/${AGENT}`, queryClient);
    const card = await openKeys();
    await userEvent.click(within(card).getByRole("button", { name: "Rotate key 2" }));
    const dialog = await screen.findByRole("dialog", { name: `Rotate key 2 for ${HOSTILE}` });
    expect(dialog).toHaveTextContent(
      `This issues a new API key for ${HOSTILE}. Key 2 keeps working until you revoke it, so you can update the tool that uses it first.`,
    );
    expect(document.querySelector("img")).toBeNull();
    const confirm = within(dialog).getByRole("button", { name: "Issue the new key" });
    expect(confirm).toBeDisabled();
    expect(within(dialog).getByLabelText("Lifetime")).toHaveValue("");
    await userEvent.selectOptions(within(dialog).getByLabelText("Lifetime"), "2160");
    await userEvent.click(confirm);
    const shown = await screen.findByRole("dialog", { name: "Copy the API key now" });
    expect(within(shown).getByLabelText("API key (copy it now)")).toHaveValue(TOKEN);
    expect(shown).toHaveTextContent(
      "Next, put this key where key 2 is used, such as the Tines story's credential, then revoke key 2 on this page.",
    );
    const issued = calls.find((call) => call.path.endsWith("/credentials/issue"));
    expect(issued?.body).toEqual({ lifetime: "2160", replaces: KEY });
    await userEvent.click(within(shown).getByRole("button", { name: "I have copied it" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(window.location.href).not.toContain(TOKEN);
    await waitFor(() => {
      expect(JSON.stringify(queryClient.getMutationCache().getAll().map((mutation) => mutation.state))).not.toContain(TOKEN);
    });
    expect(JSON.stringify(queryClient.getQueryCache().getAll().map((query) => query.state))).not.toContain(TOKEN);
  });

  it("shows a refused rotation and no secret", async () => {
    serve({
      [`/api/console/v1/agents/${AGENT}/credentials/issue`]: () =>
        json({ code: "CONFLICT", detail: "The change conflicts with the current state." }, 409),
    });
    mount(<AgentDetailView detail={GOVERNED} />);
    const card = await openKeys();
    await userEvent.click(within(card).getByRole("button", { name: "Rotate key 2" }));
    const dialog = await screen.findByRole("dialog", { name: `Rotate key 2 for ${HOSTILE}` });
    await userEvent.selectOptions(within(dialog).getByLabelText("Lifetime"), "720");
    await userEvent.click(within(dialog).getByRole("button", { name: "Issue the new key" }));
    expect(await within(dialog).findByRole("alert")).toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: "Copy the API key now" })).toBeNull();
  });
});

describe("a key notice", () => {
  it("names the key and the agent, with a never-labelled agent by its handle", async () => {
    serve({});
    mount(<KeyNotice notice={{ ...NOTICE, principal_label: null }} />);
    const link = await screen.findByRole("link", { name: "Key 2 for Agent 3" });
    expect(link).toHaveAttribute("href", `/agents/${AGENT}?section=connection`);
  });
});

describe("the agent page's own link (#678)", () => {
  it("copies the agent's address by its identifier, and nothing the page holds", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    mount(<AgentDetailView detail={GOVERNED} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy link" }));
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/agents/${AGENT}`);
  });
});
