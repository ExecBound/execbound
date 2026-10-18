// SPDX-License-Identifier: AGPL-3.0-only
// What this person opened recently in this browser (#678), for the palette's Recent group.
//
// Stored: the kind and an identifier only, `{k: "page", to: "/agents"}` or `{k: "execution",
// id: "<uuid>"}`, never a label, a hostname, a target or any string a server sent. Keyed by tenant
// and principal, `eb.recent.v1.<tenant>.<principal>`, so another person or another workspace in the
// same browser sees none of it. Read back strictly: a page must be one of the navigation's paths
// and an id a UUID, and anything else discards the whole list. A record is shown only once the
// scoped search finds it again, so one whose access was revoked, or which belongs to another
// space, is absent. Every read and write is inside try/catch; a failure means no recents.

import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";

import { readApprovalOptions } from "../api/@tanstack/react-query.gen";
import { useEdition } from "../edition/context";
import { allEntries, entryFor } from "../shell/navigation";
import { useSession } from "./session";

export type Recent = { k: "page"; to: string } | { k: "execution"; id: string };

export interface RecentOwner {
  tenant?: string;
  principal?: string;
}

export const RECENT_MAX = 8;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function storageKey(owner: RecentOwner): string | null {
  if (owner.tenant === undefined || owner.tenant === "" || owner.principal === undefined || owner.principal === "") return null;
  return `eb.recent.v1.${owner.tenant}.${owner.principal}`;
}

function valid(item: unknown, paths: ReadonlySet<string>): item is Recent {
  if (typeof item !== "object" || item === null || Array.isArray(item)) return false;
  const keys = Object.keys(item).sort().join(",");
  const value = item as Record<string, unknown>;
  if (keys === "k,to") return value.k === "page" && typeof value.to === "string" && paths.has(value.to);
  if (keys === "id,k") return value.k === "execution" && typeof value.id === "string" && UUID.test(value.id);
  return false;
}

/** The list, newest first, or none where anything in it is not what this version writes. */
export function readRecents(owner: RecentOwner, paths: ReadonlySet<string>): Recent[] {
  const key = storageKey(owner);
  if (key === null) return [];
  try {
    const raw = window.localStorage.getItem(key);
    if (raw === null) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length > RECENT_MAX || !parsed.every((item) => valid(item, paths))) return [];
    return parsed;
  } catch {
    return [];
  }
}

const same = (a: Recent, b: Recent) =>
  a.k === "page" ? b.k === "page" && a.to === b.to : b.k === "execution" && a.id === b.id;

/** Puts `recent` first, without duplicates, keeping the newest eight. */
export function recordRecent(owner: RecentOwner, recent: Recent, paths: ReadonlySet<string>): void {
  const key = storageKey(owner);
  if (key === null || !valid(recent, paths)) return;
  const kept: Recent = recent.k === "page" ? { k: "page", to: recent.to } : { k: "execution", id: recent.id };
  const next = [kept, ...readRecents(owner, paths).filter((item) => !same(item, kept))].slice(0, RECENT_MAX);
  try {
    window.localStorage.setItem(key, JSON.stringify(next));
  } catch {
    // Not kept; nothing else depends on it.
  }
}

/** Empties the list for this person in this browser. */
export function clearRecents(owner: RecentOwner): void {
  const key = storageKey(owner);
  if (key === null) return;
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Nothing was kept, or nothing can be removed.
  }
}

/** The approval an address opens, core's or a workspace's: `/approvals/<id>`. */
export function approvalIn(pathname: string): string | undefined {
  const match = /^(?:\/workspaces\/[0-9a-f-]{36})?\/approvals\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(pathname);
  return match?.[1];
}

/**
 * Records each page this person arrives at: a record open over Activity as that record, an
 * approval as its execution once the page's own read of it is in the cache (observed, never asked
 * for), and anything else as the navigation entry it belongs to, so an agent's page is recorded as
 * Agent connections. Approvals are kept as executions because the search finds an execution by its
 * id through the reader's spaces, where it finds an approval only for the people assigned to it.
 */
export function useRecordRecents(pathname: string, open: string | undefined): void {
  const session = useSession();
  const { navigation } = useEdition();
  const approvalId = approvalIn(pathname);
  const approval = useQuery({ ...readApprovalOptions({ path: { approval_id: approvalId ?? "" } }), enabled: false }).data;
  const features = { assistant: session.assistant, invitations: session.invitations, permissions: session.permissions };
  const entry = approvalId === undefined ? entryFor(pathname, navigation, session.role, features) : undefined;
  const owner = useMemo(() => ({ tenant: session.tenant.id, principal: session.person.id }), [session.tenant.id, session.person.id]);
  const paths = useMemo(() => new Set(allEntries(navigation).map((item) => item.to)), [navigation]);
  const execution = approvalId !== undefined ? approval?.item.execution_id : pathname === "/activity" ? open : undefined;
  const page = approvalId === undefined && !(pathname === "/activity" && open !== undefined) ? entry?.to : undefined;
  useEffect(() => {
    if (execution !== undefined) recordRecent(owner, { k: "execution", id: execution }, paths);
    else if (page !== undefined) recordRecent(owner, { k: "page", to: page }, paths);
  }, [owner, paths, execution, page, pathname]);
}
