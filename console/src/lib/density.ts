// SPDX-License-Identifier: AGPL-3.0-only
// A table's density is remembered per browser, like the rail (#333). localStorage
// can be absent or refuse; the console then starts comfortable.

import { useCallback, useState } from "react";

import type { Density } from "../components/ui/Table";

const KEY = "eb.density";

export function readDensity(): Density {
  try {
    return window.localStorage.getItem(KEY) === "compact" ? "compact" : "comfortable";
  } catch {
    return "comfortable";
  }
}

export function useDensity(): [Density, () => void] {
  const [density, setDensity] = useState<Density>(readDensity);
  const toggle = useCallback(() => {
    setDensity((current) => {
      const next: Density = current === "compact" ? "comfortable" : "compact";
      try {
        window.localStorage.setItem(KEY, next);
      } catch {
        // Nothing to remember it in; the choice lasts until the page is left.
      }
      return next;
    });
  }, []);
  return [density, toggle];
}
