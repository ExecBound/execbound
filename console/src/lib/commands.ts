// SPDX-License-Identifier: AGPL-3.0-only
// The palette's commands that open another page's dialog (#678): "Add agent" goes to Agent
// connections and opens its Add agent dialog, as pressing the page's own button would. One pending
// command is held in memory, never in the address or in storage, with the moment it was asked
// for; the page's dialog takes it once, within five seconds, by its name. The bus opens a dialog
// and nothing else: the dialog's own step-up, checks and the server's answer are untouched.

import { useEffect, useRef } from "react";

export type CommandName = "add-agent" | "add-user" | "new-space" | "issue-key";

/** How long a command waits for its page to mount. */
export const COMMAND_MS = 5000;

let pending: { name: CommandName; at: number } | null = null;
const listeners = new Set<() => void>();

/** Asks the page that owns `name` to open its dialog. */
export function requestCommand(name: CommandName): void {
  pending = { name, at: Date.now() };
  for (const listener of [...listeners]) listener();
}

function take(name: CommandName): boolean {
  if (pending?.name !== name) return false;
  const fresh = Date.now() - pending.at < COMMAND_MS;
  pending = null;
  return fresh;
}

/** Opens the dialog when its command is asked for, once, now or while the page stays mounted. */
export function useCommand(name: CommandName, open: () => void): void {
  const latest = useRef(open);
  useEffect(() => {
    latest.current = open;
  });
  useEffect(() => {
    const check = () => {
      if (take(name)) latest.current();
    };
    check();
    listeners.add(check);
    return () => {
      listeners.delete(check);
    };
  }, [name]);
}

/** Forgets a pending command, between tests. */
export function forgetCommands(): void {
  pending = null;
}
