// SPDX-License-Identifier: AGPL-3.0-only
// The workspaces this browser opened last, so the menu offers them next after those the server
// says the account entered most recently (#678). Stored: up to ten tenant ids, most recent
// first, and nothing else. It cannot be keyed per account, since the
// session view names none, so it is cleared on sign-out and by "Clear recent", and it only orders
// what the server listed: another account in the same browser gains no workspace from it. Every
// read and write is inside try/catch; a missing, malformed or throwing store leaves the server's
// order.

import type { WorkspaceItem } from "../api/types.gen";
import { RECENT_WORKSPACES as KEY } from "./workspaces";
const MAX = 10;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

export function readRecent(): string[] {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(KEY) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((id): id is string => typeof id === "string" && UUID.test(id)).slice(0, MAX);
  } catch {
    return [];
  }
}

export function rememberRecent(id: string | undefined): void {
  if (id === undefined || !UUID.test(id)) return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify([id, ...readRecent().filter((known) => known !== id)].slice(0, MAX)));
  } catch {
    // A store that cannot be written orders nothing.
  }
}

/**
 * The order the menu shows: the current workspace; then those the account has entered, most
 * recent first, by the server's `last_entered_at` (wherever the account entered them); then
 * this browser's recent ones, most recent first; then the rest in the server's order. The one
 * place that sorts.
 */
export function ordered(items: readonly WorkspaceItem[], recent: readonly string[]): WorkspaceItem[] {
  const rank = (item: WorkspaceItem) => {
    if (item.current) return -1;
    const at = recent.indexOf(item.tenant_id);
    return at === -1 ? MAX : at;
  };
  const entered = (item: WorkspaceItem) => (item.last_entered_at ? Date.parse(item.last_entered_at) : Number.NaN);
  const byEntry = (a: WorkspaceItem, b: WorkspaceItem) => {
    const [x, y] = [entered(a), entered(b)];
    if (Number.isNaN(x)) return Number.isNaN(y) ? 0 : 1;
    return Number.isNaN(y) ? -1 : y - x;
  };
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => Number(b.item.current) - Number(a.item.current) || byEntry(a.item, b.item) || rank(a.item) - rank(b.item) || a.index - b.index)
    .map(({ item }) => item);
}
