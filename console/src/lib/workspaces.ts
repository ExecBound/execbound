// SPDX-License-Identifier: AGPL-3.0-only
// The account's own workspaces (#678), read with the session and never on a timer of its own,
// so never in a hidden tab. Switching and the order the menu shows live beside it, in
// `workspace-switch.ts` and `workspace-recents.ts`, which load with the menu and the palette.

import { useQuery } from "@tanstack/react-query";

import { readWorkspacesOptions } from "./shell-api";
import type { WorkspaceItem } from "../api/types.gen";
import { useSession } from "./session";

export function useWorkspaces() {
  const session = useSession();
  return useQuery({ ...readWorkspacesOptions(), enabled: session.canSwitchWorkspaces, staleTime: 30_000 });
}

/** How many other workspaces hold approvals waiting for this account. */
export function waitingElsewhere(items: readonly WorkspaceItem[]): number {
  return items.filter((item) => !item.current && item.waiting_state === "counted" && (item.waiting ?? 0) > 0).length;
}

/** Where this browser keeps the workspaces it opened last (`workspace-recents.ts`). */
export const RECENT_WORKSPACES = "eb.recent.v1.workspaces";

/** Forget them: on sign-out, and with "Clear recent". */
export function clearRecentWorkspaces(): void {
  try {
    window.localStorage.removeItem(RECENT_WORKSPACES);
  } catch {
    // Nothing was kept, or nothing can be.
  }
}
