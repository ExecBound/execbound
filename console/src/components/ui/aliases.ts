// SPDX-License-Identifier: AGPL-3.0-only
// The words people search for each of core's pages by (#678), beside its label and its address's
// own segment. They load with the palette, not with every page. An edition's entry carries its
// own words on the entry.

import type { NavigationEntry } from "../../shell/navigation";

export const ALIASES: Readonly<Record<string, readonly string[]>> = {
  "/approvals": ["Reviews", "Decisions", "Queue"],
  "/activity": ["Requests", "History", "Audit"],
  "/board": ["Board", "Live"],
  "/policy": ["Bundles", "Policy versions", "Rules"],
  "/agents": ["Agents"],
  "/people": ["People", "Members", "Teammates"],
  "/access": ["Groups", "Roles", "Permissions"],
  "/credentials": ["API tokens", "Bearer tokens", "Access keys", "Agent credentials"],
  "/approvers": ["Approvers", "Reviewers", "Approver scopes"],
  "/spaces": ["Space"],
  "/monitor": ["Findings", "Sources", "Tines"],
  "/welcome": ["Setup", "Onboarding"],
  "/tenant": ["Tenant", "Organisation", "Organization", "Mode", "Emergency stop"],
  "/help": ["Support", "Documentation", "Keyboard"],
  "/settings": ["Settings", "Profile", "Password", "MFA"],
};

/** A page's search words: core's table, then whatever the entry carries. */
export function aliasesOf(entry: Pick<NavigationEntry, "aliases"> & { to?: string }): readonly string[] {
  return [...(entry.to === undefined ? [] : (ALIASES[entry.to] ?? [])), ...(entry.aliases ?? [])];
}
