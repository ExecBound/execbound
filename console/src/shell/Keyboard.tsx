// SPDX-License-Identifier: AGPL-3.0-only
// The shell's single-key shortcuts (#678): `?` opens the keyboard list, `g` then a letter goes
// to a page, and `j` and `k` move along the rows of the list on the page, wherever the focus is.
// They load with the shell's after-paint layer once the page has settled, so the first load of
// every page, an approval link opened cold among them, carries none of them; Ctrl K or Cmd K is
// the shell's own and works from the first paint.
//
// After `g`, the next key belongs to the sequence alone and must come within a second: `g` then
// `?` is Help, never the list. Nothing acts while someone types in a field, over an open dialog,
// with Ctrl, Cmd or Alt held, on a repeated key, or while the single-key shortcuts are off; Shift
// does not block, because `?` needs it. A key only ever opens a page this person can see.

import { useEffect } from "react";

import { singleKeysEnabled } from "../lib/keys";
import { useShellActions } from "./actions";
import type { NavigationEntry } from "./navigation";

/** Whether a key press is someone typing into a field, where no shortcut may act. */
export function typing(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement &&
    (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
  );
}

/** Whether a dialog is open: no shortcut acts over one. */
export function dialogOpen(): boolean {
  return document.querySelector('[role="dialog"]') !== null;
}

/**
 * The attribute a list puts on its container to take `j` and `k`: its value is the selector of
 * the rows' own links or buttons, `data-rows=".row-link"`.
 */
export const ROWS = "data-rows";

/** How long the second key of a `g` sequence may wait. */
export const SEQUENCE_MS = 1000;

export interface SequenceOptions {
  /** The entries this person can see; a key reaches nothing else. */
  entries: readonly NavigationEntry[];
  navigate: (to: string) => void;
  openShortcuts: () => void;
  now?: () => number;
}

/** A keydown handler holding one pending `g`. */
export function createSequence({
  entries,
  navigate,
  openShortcuts,
  now = Date.now,
}: SequenceOptions): (event: KeyboardEvent) => void {
  let pending: number | null = null;
  return (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey || event.repeat) return;
    if (typing(event.target) || dialogOpen() || !singleKeysEnabled()) {
      pending = null;
      return;
    }
    if (pending !== null) {
      const fresh = now() - pending <= SEQUENCE_MS;
      pending = null;
      if (fresh) {
        const entry = entries.find((candidate) => candidate.key === event.key);
        if (entry !== undefined) {
          event.preventDefault();
          navigate(entry.to);
        }
        return;
      }
    }
    if (event.key === "g") {
      pending = now();
      return;
    }
    if (event.key === "j" || event.key === "k") {
      if (moveAlongRows(event.key === "j" ? 1 : -1)) event.preventDefault();
      return;
    }
    if (event.key === "?") {
      event.preventDefault();
      openShortcuts();
    }
  };
}

/**
 * `j` and `k` along the rows of the list marked with `data-rows`: from no focused row they focus
 * the first, from a row the next or the previous, and at either end they stay. The row's own link
 * or button takes the focus, so Enter opens it as a click would. Activity and the Approvals queue
 * behave the same.
 */
export function moveAlongRows(step: 1 | -1, root: ParentNode = document): boolean {
  const list = root.querySelector<HTMLElement>(`[${ROWS}]`);
  const selector = list?.getAttribute(ROWS);
  if (list === null || selector === null || selector === undefined || selector === "") return false;
  const rows = Array.from(list.querySelectorAll<HTMLElement>(selector));
  if (rows.length === 0) return false;
  const index = rows.findIndex((row) => row === document.activeElement);
  const next = index === -1 ? 0 : Math.min(Math.max(index + step, 0), rows.length - 1);
  rows[next]?.focus();
  return true;
}

/** Installs the handler for the entries given; renders nothing. */
export function Keyboard({ entries, navigate }: { entries: readonly NavigationEntry[]; navigate: (to: string) => void }) {
  const { openShortcuts } = useShellActions();
  useEffect(() => {
    const onKey = createSequence({ entries, navigate, openShortcuts });
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [entries, navigate, openShortcuts]);
  return null;
}
