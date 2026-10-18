// SPDX-License-Identifier: AGPL-3.0-only
// The section a page belongs to, for a switch that keeps the person's place and a stale tab's
// link (#678): a page root, never a record, a query or another address. The server holds the
// same closed set (`Section`), and every member here must be one of its members and back.

import type { SelectWorkspaceData } from "../api/types.gen";
import { allEntries } from "../shell/navigation";

export type Section = NonNullable<SelectWorkspaceData["body"]["section"]>;

const MEMBERS: Record<Section, true> = {
  "/": true,
  "/approvals": true,
  "/activity": true,
  "/board": true,
  "/policy": true,
  "/agents": true,
  "/people": true,
  "/access": true,
  "/credentials": true,
  "/approvers": true,
  "/spaces": true,
  "/monitor": true,
  "/welcome": true,
  "/tenant": true,
  "/help": true,
  "/settings": true,
};
export const SECTIONS = Object.keys(MEMBERS) as readonly Section[];

export function isSection(value: string): value is Section {
  return Object.hasOwn(MEMBERS, value);
}

const SCOPED_APPROVAL = /^\/workspaces\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\/approvals\/[^/]+(?:\/classic)?$/;

/**
 * The root of the section `pathname` is in, and its name: the navigation entry whose address it
 * is, else the longest one it lies under, else Home. Every entry counts, whoever may see it, so
 * the answer never depends on the reader; a workspace's own approval address is Approvals.
 */
export function sectionRoot(pathname: string): { to: string; label: string } {
  if (SCOPED_APPROVAL.test(pathname)) return { to: "/approvals", label: "Approvals" };
  let found: { to: string; label: string } | undefined;
  for (const entry of allEntries()) {
    if (entry.to === pathname) return { to: entry.to, label: entry.label };
    if (entry.to !== "/" && pathname.startsWith(entry.to + "/") && entry.to.length > (found?.to.length ?? 0)) found = entry;
  }
  return found === undefined ? { to: "/", label: "Home" } : { to: found.to, label: found.label };
}
