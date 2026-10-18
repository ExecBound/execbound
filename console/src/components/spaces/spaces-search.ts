// SPDX-License-Identifier: AGPL-3.0-only
export type SpacesState = "active" | "archived" | "all";

export interface SpacesSearch {
  /** Which space's detail is open; the page's state lives in the URL, never in a component. */
  open?: string;
  q: string;
  state: SpacesState;
}

export const DEFAULT_SPACES_SEARCH: SpacesSearch = { q: "", state: "active" };

export const STATES: readonly { value: SpacesState; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "archived", label: "Archived" },
  { value: "all", label: "All" },
];
export const QUERY_MAX = 80;

/** The route's search parameters, read defensively: anything else falls back to the default. */
export function parseSpacesSearch(raw: Readonly<Record<string, unknown>>): SpacesSearch {
  const open = typeof raw.open === "string" && raw.open !== "" ? raw.open : undefined;
  const q = typeof raw.q === "string" ? raw.q.slice(0, QUERY_MAX) : "";
  const wanted = STATES.find((option) => option.value === raw.state)?.value ?? "active";
  return open === undefined ? { q, state: wanted } : { open, q, state: wanted };
}
