// SPDX-License-Identifier: AGPL-3.0-only
import { expect, it } from "vitest";

import type { ServiceLinksView, SessionView } from "../api/types.gen";
import { NAVIGATION, visible } from "../shell/navigation";
import { summarise } from "./SessionProvider";
import { can, canAnywhere, NO_SERVICE, PLACEHOLDER } from "./session";

const view: SessionView = {
  generation: "test-generation", can_switch_workspaces: false,
  identity: { principal_id: "admin-a", kind: "ADMIN", label: "Space administrator" },
  tenant: { tenant_id: "tenant", name: "Example", mode: "ENFORCE", approval_deadline_seconds: 900 },
  access: {
    managed: false,
    roles: ["policy_manager", "approver"],
    permissions: ["console.read", "policy.manage", "approvals.decide"],
    workspace_permissions: [],
    space_permissions: { a: ["console.read", "policy.manage", "approvals.decide"] },
  },
  space: { space_id: "a", name: "Assigned Space", archived: false },
  spaces: 2, all_spaces: true, csrf_token: "test", release: null,
  expires_at: "2026-09-22T20:00:00Z", ends_at: "2026-09-20T04:00:00Z", end_reason: "sign_in", stop: null, assistant: false, invitations: false, mail: true, features: [],
  service: NO_SERVICE,
};

it("keeps a legacy Space administrator's setup routes without offering workspace access changes", () => {
  for (const space of [view.space, null]) {
    const session = summarise({ ...view, space });
    const routes = visible(NAVIGATION, session.role, { permissions: session.permissions }).map((entry) => entry.to);
    expect(routes).toContain("/agents");
    expect(routes).toContain("/credentials");
    expect(routes).not.toContain("/access");
    expect(routes).not.toContain("/people");
    expect(can(session, "workspace.manage")).toBe(false);
  }
});

it("answers what a person holds in any space apart from what the current space grants", () => {
  // Reading one space while deciding approvals in another: the current view grants no review,
  // and a link to a record named by its id still reaches the space where they hold one.
  const reading = summarise({
    ...view,
    identity: { ...view.identity, kind: "HUMAN_APPROVER" },
    access: {
      ...view.access, managed: true, roles: ["approver", "viewer"],
      permissions: ["console.read", "approvals.decide"],
      space_permissions: { a: ["console.read"], b: ["console.read", "approvals.decide"] },
    },
  });
  expect(can(reading, "approvals.decide")).toBe(false);
  expect(canAnywhere(reading, "approvals.decide")).toBe(true);
  const nowhere = summarise({ ...view, access: { ...view.access, permissions: ["console.read"], space_permissions: { a: ["console.read"] } } });
  expect(canAnywhere(nowhere, "approvals.decide")).toBe(false);
  // A fixture without the set falls back to the current view's answer, and the placeholder holds nothing.
  expect(canAnywhere({ role: "APPROVER" }, "approvals.decide")).toBe(true);
  expect(canAnywhere(PLACEHOLDER, "approvals.decide")).toBe(false);
});

it("carries the plugin features the server reports, by name (#496)", () => {
  expect(summarise(view).features).toEqual([]);
  expect(summarise({ ...view, features: ["an_edition_feature"] }).features).toEqual(["an_edition_feature"]);
});

it("reads no features from a view that names no list, as a rolled-back server's (#496)", () => {
  const unlisted: Omit<SessionView, "features"> & { features?: string[] } = { ...view };
  delete unlisted.features;
  expect(summarise(unlisted as SessionView).features).toEqual([]);
});

it("carries the deployment's service links, and none where it names none (#496)", () => {
  expect(summarise(view).service).toEqual(NO_SERVICE);
  const service = { ...NO_SERVICE, support_email: "support@example.com", status_url: "https://example.com/status" };
  expect(summarise({ ...view, service }).service).toEqual(service);
});

it("reads no Source link from service links that name none, as an older server's (#496)", () => {
  const older: Partial<ServiceLinksView> = { ...NO_SERVICE, help_url: "https://example.com/help" };
  delete older.source_url;
  const service = summarise({ ...view, service: older as ServiceLinksView }).service;
  expect(service?.source_url).toBeNull();
  expect(service?.help_url).toBe("https://example.com/help");
});

it("reads no service links from a view that names none, as a rolled-back server's (#496)", () => {
  const unlisted: Omit<SessionView, "service"> & { service?: SessionView["service"] } = { ...view };
  delete unlisted.service;
  expect(summarise(unlisted as SessionView).service).toEqual(NO_SERVICE);
});

it("carries the signed-in principal's id and the tenant's, which per-person browser state is keyed by (#678)", () => {
  const session = summarise(view);
  expect(session.person.id).toBe(view.identity.principal_id);
  expect(session.tenant.id).toBe(view.tenant.tenant_id);
});
