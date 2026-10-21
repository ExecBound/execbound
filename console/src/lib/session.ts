// SPDX-License-Identifier: AGPL-3.0-only
// What the shell knows about the signed-in person. SessionProvider fills this from
// GET /api/console/v1/session and renders nothing beneath it until the view arrives.
// PLACEHOLDER is the context's default, for a component rendered outside the provider, and its
// UNKNOWN role grants nothing (`can`).

import { createContext, useContext } from "react";

import type { ServiceLinksView } from "../api/types.gen";

export type Role = "ADMIN" | "APPROVER" | "POLICY_MANAGER" | "VIEWER" | "UNKNOWN";
export type Mode = "ENFORCE" | "OBSERVE" | "UNKNOWN";

export interface SessionStop {
  at: string;
  by: string;
  reason: string;
  /** The administrator who activated it, by name, for an administrator's session alone; `null`
   * for everyone else, whose banner says "an administrator" (#678). */
  byName: string | null;
}

/** The space the session is looking at; `null` is "All spaces". */
export interface SessionSpace {
  id: string;
  name: string;
  archived: boolean;
}

export interface SessionSummary {
  role: Role;
  /** Fresh server-resolved permissions for the current view. */
  permissions?: readonly string[];
  /**
   * The permissions held in at least one of this person's spaces, whatever the current view.
   * A record named by its own id is read by membership rather than by the current space, so a
   * link to one asks this set (`canAnywhere`) rather than the current view's.
   */
  permissionsAnywhere?: readonly string[];
  mode: Mode;
  tenant: { id?: string; name: string; detail: string };
  canSwitchWorkspaces?: boolean;
  /**
   * The space this session is looking at, `null` meaning "All spaces". The space id is the
   * first identifier the client is given; `tenant_id` still never reaches it.
   */
  space: SessionSpace | null;
  /** How many spaces this person can see at all; one is a tenant that never made a second. */
  spaces: number;
  /** Whether "All spaces" is worth offering: a visible set of one has nothing to switch between. */
  allSpaces: boolean;
  /** `id` is the signed-in principal's id, which binds a kept draft to the person who typed it
   * (`lib/drafts.ts`); absent in a fixture that names none, where nothing is kept. */
  person: { label: string; detail: string; initials: string; id?: string };
  /** The tenant's active emergency stop, which the banner and the top bar show. */
  stop: SessionStop | null;
  /**
   * Whether this deployment has an assistant at all (#330). It arrives with the session, so
   * the shell knows before it paints: a console built for a deployment without one shows no
   * navigation entry, no top bar button and no Explain, not even for a frame.
   */
  assistant: boolean;
  /**
   * Whether this session administers a plugin's invitation codes (#178, #204). True only where
   * a loaded plugin reports the `invitations` feature for this session, so every other
   * console shows no door to a page that would answer 404. Whether this person is a
   * tenant administrator is the area's own check, made in the database on every request.
   */
  invitations: boolean;
  /**
   * Whether this deployment has a mail relay, so a teammate invitation reaches anyone. The
   * people page offers to invite by email only where it does, and otherwise points at Add user.
   */
  mail: boolean;
  /**
   * The plugin features that hold for this session, by name (#496). Core names none of
   * them; an edition reads its own, such as the hosted service's `create_workspace`, and the
   * command palette compares an edition link's own `feature` with them.
   */
  features: readonly string[];
  /**
   * The deployment's support address and public pages (#496): Help's contact and plans cards,
   * the footer's Privacy, Terms, Status and Source, My account's support line and the requests
   * card's guidance. Each is `null` where the deployment names none, and a link without an
   * address is not shown. The server names Source, the public repository, unless the deployment
   * points it elsewhere or turns it off. Absent in a fixture that names none, which reads as none
   * at all (`useService`).
   */
  service?: ServiceLinksView;
  /**
   * The hard end no renewal passes, and why it falls then: two days after signing in
   * (`sign_in`), or the expiry of the setup credential the session was opened with
   * (`setup_credential`). Absent in a fixture that names none, where no notice is shown (#678).
   */
  endsAt?: string;
  endReason?: "sign_in" | "setup_credential";
  /**
   * The session's own token, for the one control that posts a form rather than calling the
   * API: sign out (#333). It is empty until the session view arrives, and the button
   * does not exist until it is filled.
   */
  csrf: string;
}

export const PLACEHOLDER: SessionSummary = {
  role: "UNKNOWN",
  mode: "UNKNOWN",
  tenant: { name: "Tenant", detail: "" },
  space: null,
  spaces: 1,
  allSpaces: false,
  person: { label: "Signed in", detail: "", initials: "" },
  stop: null,
  assistant: false,
  invitations: false,
  mail: false,
  features: [],
  csrf: "",
};

export const SessionContext = createContext<SessionSummary>(PLACEHOLDER);

export function useSession(): SessionSummary {
  return useContext(SessionContext);
}

/** A deployment that names no support address and no public page. */
export const NO_SERVICE: ServiceLinksView = {
  support_email: null,
  help_url: null,
  status_url: null,
  privacy_url: null,
  terms_url: null,
  plans_url: null,
  security_url: null,
  privacy_requests_url: null,
  source_url: null,
  operator: null,
};

/** The deployment's service links, or none where the session carries none. */
export function useService(): ServiceLinksView {
  return useSession().service ?? NO_SERVICE;
}

/**
 * Whether the person is looking at All spaces in a tenant that has more than one (#678): no Space
 * is selected, so nothing on the page is "this Space's". A tenant with one space always reads it.
 */
export function inAllSpaces(session: Pick<SessionSummary, "space" | "spaces">): boolean {
  return session.space === null && session.spaces > 1;
}

export function can(session: Pick<SessionSummary, "role" | "permissions">, permission: string): boolean {
  if (session.permissions !== undefined) return session.permissions.includes(permission);
  // Compatibility for isolated UI fixtures; live sessions always carry permissions.
  if (session.role === "UNKNOWN") return false;
  if (permission === "console.read") return true;
  if (permission === "approvals.decide") return session.role === "ADMIN" || session.role === "APPROVER";
  if (permission === "policy.manage") return session.role === "ADMIN" || session.role === "POLICY_MANAGER";
  return (permission === "access.manage" || permission === "workspace.manage") && session.role === "ADMIN";
}

/** Whether a permission is held in any of this person's spaces, for a link to one named record. */
export function canAnywhere(
  session: Pick<SessionSummary, "role" | "permissions" | "permissionsAnywhere">,
  permission: string,
): boolean {
  if (session.permissionsAnywhere !== undefined) return session.permissionsAnywhere.includes(permission);
  return can(session, permission);
}
