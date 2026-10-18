// SPDX-License-Identifier: AGPL-3.0-only
// The board's search parameters, in a module of their own that imports no component.
//
// TanStack Router splits only a route's component into its lazy chunk; `validateSearch` and
// everything it reaches stay in the shell's static bundle (#381). A parser that lives beside a
// component therefore drags that component, and whatever it imports, into every page load. This
// module has no import at all, so the shell carries the parser and nothing else.

export interface BoardSearch {
  /** Absent means live. `?live=false`, and the server-rendered page's `?live=0`, still the board. */
  live?: boolean;
  window?: "1h" | "24h";
}

export function paused(value: unknown): boolean {
  return value === false || value === "0" || value === "false";
}

export function boardSearch(search: Record<string, unknown>): BoardSearch {
  if (search.window === "1h" || search.window === "24h") {
    return { window: search.window, live: false };
  }
  return paused(search.live) ? { live: false } : {};
}

export function periodLabel(seconds: number): string {
  if (seconds === 86400) return "Last 24 hours";
  if (seconds === 3600) return "Last hour";
  return "Last fifteen minutes";
}
