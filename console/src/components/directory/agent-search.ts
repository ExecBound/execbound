// SPDX-License-Identifier: AGPL-3.0-only
// The filters exactly as the page takes them (#228).
export const FILTERS = {
  state: ["active", "deactivated", "gone", "all"],
  active: ["any", "yes", "no"],
  population: ["all", "registered", "bound", "governed", "discovered"],
  source: ["all", "entra_agent_id", "tines"],
  ungoverned: ["any", "yes"],
} as const;

type Choice<K extends keyof typeof FILTERS> = (typeof FILTERS)[K][number];

export interface AgentsSearch {
  state: Choice<"state">;
  active: Choice<"active">;
  population: Choice<"population">;
  source: Choice<"source">;
  ungoverned: Choice<"ungoverned">;
  cursor?: string;
}

export const DEFAULT_SEARCH: AgentsSearch = {
  state: "active",
  active: "any",
  population: "all",
  source: "all",
  ungoverned: "any",
};

function choice<K extends keyof typeof FILTERS>(key: K, value: unknown): Choice<K> {
  const options: readonly string[] = FILTERS[key];
  return (typeof value === "string" && options.includes(value) ? value : DEFAULT_SEARCH[key]) as Choice<K>;
}

/** The search parameters a URL carries, each held to its choices; anything else is the default. */
export function parseAgentsSearch(raw: Readonly<Record<string, unknown>>): AgentsSearch {
  const search: AgentsSearch = {
    state: choice("state", raw.state),
    active: choice("active", raw.active),
    population: choice("population", raw.population),
    source: choice("source", raw.source),
    ungoverned: choice("ungoverned", raw.ungoverned),
  };
  if (typeof raw.cursor === "string" && raw.cursor !== "") search.cursor = raw.cursor;
  return search;
}
