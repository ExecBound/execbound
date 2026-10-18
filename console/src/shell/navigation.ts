// SPDX-License-Identifier: AGPL-3.0-only
// The navigation list (#333). Every page adds itself by one line here and one
// route file; the sidebar, the phone tab bar, the breadcrumbs and the command palette all read
// this list, so a page is reachable everywhere the moment it exists.

import { can, type Role } from "../lib/session";
import type { IconName } from "./icons";

export type Group = "Agent security" | "Team & access" | "Visibility";

export interface NavigationEntry {
  label: string;
  to: string;
  icon: IconName;
  group?: Group;
  /** Who sees the entry; unknown sessions stay closed until current access is loaded. */
  roles: readonly Role[];
  permission?: string;
  /** The count pill the entry carries, filled by the page's own query once it exists. */
  count?: "approvals" | "monitoring";
  /**
   * A feature the deployment may not have at all. An entry that names one is hidden unless
   * the caller says it is there, so a console built for a deployment without it looks as it
   * did before the feature existed rather than showing a door that answers 404 (#330).
   */
  feature?: Feature;
  /**
   * Other names people search for, so the command palette finds the page by them too. Core's
   * pages keep theirs in the palette's own table (`components/ui/aliases.ts`), which loads with
   * the palette rather than with every page; an edition's entry carries its own here.
   */
  aliases?: readonly string[];
  /** The letter that follows `g` to open the page from the keyboard, unique across entries. */
  key?: string;
  /**
   * Whether the phone's tab bar carries the entry too: `true` for everyone who sees the entry,
   * or the roles whose tab bar does. It still passes `visible` there.
   */
  phone?: boolean | readonly Role[];
  /** The tab bar's shorter label, where the sidebar's does not fit. */
  tabLabel?: string;
}

/** Features a deployment configures rather than a role grants. */
export type Feature = "assistant" | "invitations";
export type Features = Partial<Record<Feature, boolean>> & { permissions?: readonly string[] };

const EVERYONE: readonly Role[] = ["ADMIN", "APPROVER", "POLICY_MANAGER", "VIEWER"];
const ADMIN: readonly Role[] = ["ADMIN"];
/** An approver's phone opens on the queue, so its four tabs leave Home out. */
const HOME_TAB: readonly Role[] = ["ADMIN", "POLICY_MANAGER", "VIEWER"];

// The roots below and each entry's `roles` and `permission` are mirrored in `src/execbound/surfaces/sections.py` and held to it by `tests/test_workspace_sections.py`.
export const NAVIGATION: readonly NavigationEntry[] = [
  { label: "Home", to: "/", icon: "home", roles: EVERYONE, phone: HOME_TAB, key: "h" },
  {
    label: "Approvals",
    to: "/approvals",
    icon: "approvals",
    roles: EVERYONE,
    count: "approvals",
    permission: "approvals.decide",
    phone: true,
    key: "a",
  },
  {
    label: "Activity",
    to: "/activity",
    icon: "activity",
    roles: EVERYONE,
    phone: true,
    key: "c",
  },
  { label: "Ask", to: "/ask", icon: "ask", roles: EVERYONE, feature: "assistant" },
  {
    label: "Live board",
    to: "/board",
    icon: "board",
    group: "Visibility",
    roles: EVERYONE,
    phone: true,
    tabLabel: "Live",
    key: "l",
  },
  {
    label: "Policies",
    to: "/policy",
    icon: "policy",
    group: "Agent security",
    roles: EVERYONE,
    permission: "policy.manage",
    key: "p",
  },
  {
    label: "Agent connections",
    to: "/agents",
    icon: "agents",
    group: "Agent security",
    roles: ADMIN,
    key: "n",
  },
  {
    label: "Users",
    to: "/people",
    icon: "people",
    group: "Team & access",
    roles: ADMIN,
    permission: "access.manage",
    key: "u",
  },
  {
    label: "Groups & roles",
    to: "/access",
    icon: "groups",
    group: "Team & access",
    roles: ADMIN,
    permission: "access.manage",
  },
  {
    label: "API keys",
    to: "/credentials",
    icon: "credentials",
    group: "Agent security",
    roles: ADMIN,
  },
  {
    label: "Approval rules",
    to: "/approvers",
    icon: "scopes",
    group: "Team & access",
    roles: ADMIN,
    permission: "access.manage",
  },
  { label: "Spaces", to: "/spaces", icon: "spaces", group: "Team & access", roles: ADMIN },
  {
    label: "Monitoring",
    to: "/monitor",
    icon: "monitoring",
    group: "Visibility",
    roles: ADMIN,
    count: "monitoring",
    key: "m",
  },
];

/** The entries at the bottom of the sidebar: the welcome card, the tenant and the account. */
export const FOOTER: readonly NavigationEntry[] = [
  { label: "Getting started", to: "/welcome", icon: "started", roles: ADMIN },
  {
    label: "Workspace settings",
    to: "/tenant",
    icon: "tenant",
    roles: ADMIN,
    key: "s",
  },
  {
    label: "Help & support",
    to: "/help",
    icon: "help",
    roles: EVERYONE,
    key: "?",
  },
  {
    label: "My account",
    to: "/settings",
    icon: "account",
    roles: EVERYONE,
    phone: true,
  },
];

/**
 * The sidebar's main entries: core's, then an edition's (#496). Every reader of the
 * list takes its entries from here or from `allEntries`, so the order is decided once, here.
 */
export function mainEntries(extra: readonly NavigationEntry[] = []): NavigationEntry[] {
  return [...NAVIGATION, ...extra];
}

/** Every entry, in the order every reader shows them: the main entries, then the footer. */
export function allEntries(extra: readonly NavigationEntry[] = []): NavigationEntry[] {
  return [...mainEntries(extra), ...FOOTER];
}

/**
 * What a phone shows in its tab bar: the entries that ask for it (`phone`), in the list's order;
 * an approver's four, and Home for everyone else.
 *
 * An edition's entry joins them the same way, because the sidebar is not on screen under 768 px
 * and a page that is only in it is reachable on a phone by typing its address and no other way
 * (#178, #204); `visible` still decides whether this person sees it at all.
 */
export function phoneTabs(
  role: Role,
  features: Features = {},
  extra: readonly NavigationEntry[] = [],
): NavigationEntry[] {
  const tabs = allEntries(extra).filter(
    (entry) => entry.phone === true || (typeof entry.phone === "object" && entry.phone.includes(role)),
  );
  return visible(tabs, role, features);
}

export function visible(
  entries: readonly NavigationEntry[],
  role: Role,
  features: Features = {},
): NavigationEntry[] {
  // Fail closed on the feature: an entry that names one is shown only where the caller says
  // the deployment has it, so forgetting to pass it hides a page rather than offering a 404.
  return entries.filter(
    (entry) => entry.roles.includes(role) &&
      (entry.permission === undefined || can({ role, permissions: features.permissions }, entry.permission)) &&
      (entry.feature === undefined || features[entry.feature] === true),
  );
}

/**
 * The entry a pathname belongs to, for breadcrumbs and the document title, among the entries this
 * person can see: a page they cannot open (Ask where the deployment has no assistant) is named by
 * nothing, so its not-found page names itself.
 */
export function entryFor(
  pathname: string,
  extra: readonly NavigationEntry[],
  role: Role,
  features: Features,
): NavigationEntry | undefined {
  const all = visible(allEntries(extra), role, features);
  return (
    all.find((entry) => entry.to === pathname) ??
    all.find((entry) => entry.to !== "/" && pathname.startsWith(entry.to + "/"))
  );
}
