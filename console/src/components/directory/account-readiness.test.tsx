// SPDX-License-Identifier: AGPL-3.0-only
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AccessPage, ApproversPage, PersonDetail, Provider } from "../../api/types.gen";
import { answerWith as answer, renderPage } from "../../test/page";
import { AssignScope } from "./ApproversList";
import { PersonDetailView } from "./PersonDetail";

afterEach(() => { vi.unstubAllGlobals(); });

const PERSON = "22222222-2222-2222-2222-222222222222";
const TARGET = "33333333-3333-3333-3333-333333333333";
const PROVIDER = "44444444-4444-4444-4444-444444444444";
const provider: Provider = {
  provider_id: PROVIDER, name: "Example directory", state: "enabled", client_id: "example",
  issuer: "https://id.example.test", subject_claim: "sub", created_at: "2026-09-22T10:00:00Z",
  enabled_at: "2026-09-22T10:00:00Z", verified_at: "2026-09-22T10:00:00Z",
  last_sign_in_at: null, linked: 1, self_linked: false,
};
const person: PersonDetail = {
  person: { principal_id: PERSON, kind: "HUMAN_APPROVER", active: true, label: "Dana", number: 2, created_at: null, deactivated_at: null, replaced_by: null },
  sign_in: {
    email: "dana@example.test", has_password: false, pending_until: null, identities: [], invitation: null,
    link: { provider_id: PROVIDER, provider_name: "Example directory", subject: "dana",
      via: "admin", display_name: "Dana", display_username: null, last_sign_in_at: null },
  },
  credentials: [], sessions: [], scopes: [{ canonical_target_id: TARGET, action: "endpoint.isolate", labels: "Workstation" }],
  targets: [], actions: [], history: { decisions: [], sign_ins: [], events: [] }, history_limit: 20, is_self: false,
};

const access: AccessPage = {
  roles: [], groups: [], spaces: [], users: [{
    principal_id: PERSON, label: "Dana", email: null, number: 2, active: true, kind: "HUMAN_APPROVER", managed: true,
    direct_roles: [{ role: "approver", space_id: null }], inherited_roles: [],
  }],
};
function answerWith(routes: Parameters<typeof answer>[0]) {
  return answer({ "GET /api/console/v1/access": { body: access }, ...routes });
}

async function setupCard() {
  const heading = await screen.findByRole("heading", { name: "Account setup" });
  const card = heading.closest("section");
  if (card === null) throw new Error("The account setup section is missing");
  return within(card);
}

describe("account sign-in readiness", () => {
  it.each([
    ["disabled", { ...provider, state: "disabled" }],
    ["absent", null],
    ["a different provider", { ...provider, provider_id: TARGET }],
  ])("does not treat a retained link as usable when the tenant provider is %s", async (_state, current) => {
    answerWith({ "GET /api/console/v1/tenant/sign-in": { body: { provider: current } } });
    renderPage(<PersonDetailView detail={person} />);
    const setup = await setupCard();
    expect(await setup.findByText("Sign-in: directory unavailable")).toBeInTheDocument();
    expect(setup.queryByText(/They can open a request link/)).toBeNull();
    expect(setup.getByText(/Enable the linked directory/)).toBeInTheDocument();
  });

  it("waits for enabled-provider evidence before saying directory sign-in is ready", async () => {
    answerWith({});
    let resolveResponse!: (value: Response) => void;
    const response = new Promise<Response>((resolve) => { resolveResponse = resolve; });
    const previousFetch = globalThis.fetch;
    vi.stubGlobal("fetch", vi.fn((request: Request) => new URL(request.url).pathname.endsWith("/tenant/sign-in") ? response : previousFetch(request)));
    renderPage(<PersonDetailView detail={person} />);
    const setup = await setupCard();
    expect(setup.getByText("Sign-in: checking directory availability")).toBeInTheDocument();
    expect(setup.queryByText(/They can open a request link/)).toBeNull();
    resolveResponse(new Response(JSON.stringify({ provider }), { headers: { "content-type": "application/json" } }));
    expect(await setup.findByText("Sign-in: configured")).toBeInTheDocument();
    expect(await setup.findByText(/Review Approval rules for the groups/)).toBeInTheDocument();
  });

  it("shows an unavailable readiness check without claiming a linked account can sign in", async () => {
    let attempts = 0;
    answerWith({ "GET /api/console/v1/tenant/sign-in": () => ++attempts === 1
      ? { status: 503, body: { code: "UNAVAILABLE" } } : { body: { provider } } });
    renderPage(<PersonDetailView detail={person} />);
    const setup = await setupCard();
    expect(await setup.findByText("Sign-in: directory availability unknown")).toBeInTheDocument();
    expect(setup.queryByText(/They can open a request link/)).toBeNull();
    expect(setup.getByText(/Could not check directory sign-in/)).toBeInTheDocument();
    await userEvent.click(setup.getByRole("button", { name: "Check directory sign-in again" }));
    expect(await setup.findByText("Sign-in: configured")).toBeInTheDocument();
  });

  it("retains usable password sign-in when the linked directory is disabled", async () => {
    answerWith({ "GET /api/console/v1/tenant/sign-in": { body: { provider: null } } });
    renderPage(<PersonDetailView detail={{ ...person, sign_in: { ...person.sign_in, has_password: true } }} />);
    const setup = await setupCard();
    expect(setup.getByText("Sign-in: configured")).toBeInTheDocument();
    expect(await setup.findByText(/Review Approval rules for the groups/)).toBeInTheDocument();
  });
});

describe("incomplete review permission choices", () => {
  const choices: ApproversPage = {
    approvers: [{ principal_id: PERSON, label: "Dana", email: null, number: 2 }],
    targets: [{ canonical_target_id: TARGET, labels: "Workstation" }],
    actions: ["endpoint.isolate"], assignments: [],
  };
  it.each([
    { dismiss: "Cancel", missing: "targets" },
    { dismiss: "Close", missing: "approvers" },
    { dismiss: "Escape", missing: "actions" },
  ] as const)("allows $dismiss when $missing are unavailable", async ({ dismiss, missing }) => {
    const seen = answerWith({});
    renderPage(<AssignScope data={{ ...choices, [missing]: [] }} />);
    await userEvent.click(await screen.findByRole("button", { name: "Assign an approver" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Assign" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(within(dialog).getByRole("button", { name: "Close" })).toBeEnabled();
    if (dismiss === "Escape") await userEvent.keyboard("{Escape}");
    else await userEvent.click(within(dialog).getByRole("button", { name: dismiss }));
    await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
    expect(seen.filter((request) => request.method === "POST")).toHaveLength(0);
  });
});
