// SPDX-License-Identifier: AGPL-3.0-only
// Whether the console's single-key shortcuts are on (#678). The handlers themselves load after
// the shell paints (`shell/Keyboard.tsx`); only this preference is in a page's first load, for the
// sidebar's hints.
//
// Unmodified single-character shortcuts (`?`, the `g` sequences, `j` and `k`) can be turned off
// in this browser (WCAG 2.2 SC 2.1.4): speech input and stray presses trigger them otherwise.
// The choice lives in `localStorage` under `eb.single-keys`; a browser whose storage throws keeps
// them on, and nothing fails. Ctrl K or Cmd K carries a modifier and always works.

import { useSyncExternalStore } from "react";

const STORAGE_KEY = "eb.single-keys";

function stored(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) !== "off";
  } catch {
    return true;
  }
}

let enabled: boolean | undefined;
const listeners = new Set<() => void>();

/** Whether the single-key shortcuts are on in this browser; on unless someone turned them off. */
export function singleKeysEnabled(): boolean {
  enabled ??= stored();
  return enabled;
}

/** Turns the single-key shortcuts on or off here, for every switch and handler at once. */
export function setSingleKeys(on: boolean): void {
  enabled = on;
  try {
    if (on) window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, "off");
  } catch {
    // The choice still holds for this page; it is not kept.
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** The preference as React state, so every switch and the keyboard list agree without a reload. */
export function useSingleKeys(): [boolean, (on: boolean) => void] {
  const on = useSyncExternalStore(subscribe, singleKeysEnabled, () => true);
  return [on, setSingleKeys];
}

/** Forgets the in-memory value, so a test reads storage afresh. */
export function resetSingleKeysForTest(): void {
  enabled = undefined;
}
