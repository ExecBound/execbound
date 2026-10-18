// SPDX-License-Identifier: AGPL-3.0-only
// The sidebar collapses to an icon rail and the choice is remembered per browser (#333).
// localStorage can be absent or refuse; the console then simply starts open.

import { useCallback, useState } from "react";

const KEY = "eb.sidebar";

export function readRail(storage: Pick<Storage, "getItem"> | null = safeStorage()): boolean {
  try {
    return storage?.getItem(KEY) === "rail";
  } catch {
    return false;
  }
}

export function useRail(): [boolean, () => void] {
  const [rail, setRail] = useState(readRail);
  const toggle = useCallback(() => {
    setRail((current) => {
      const value = !current;
      try {
        safeStorage()?.setItem(KEY, value ? "rail" : "open");
      } catch {
        // Nothing to remember it in; the choice lasts until the page is left.
      }
      return value;
    });
  }, []);
  return [rail, toggle];
}

function safeStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
