// SPDX-License-Identifier: AGPL-3.0-only
// The filters exactly as the page takes them (#241).
export const PEOPLE_FILTERS = {
  state: ["active", "deactivated", "all"],
  kind: ["any", "HUMAN_APPROVER", "ADMIN"],
} as const;

type Choice<K extends keyof typeof PEOPLE_FILTERS> = (typeof PEOPLE_FILTERS)[K][number];

export interface PeopleSearch {
  state: Choice<"state">;
  kind: Choice<"kind">;
}

export const DEFAULT_PEOPLE_SEARCH: PeopleSearch = { state: "active", kind: "any" };

function choice<K extends keyof typeof PEOPLE_FILTERS>(key: K, value: unknown): Choice<K> {
  const options: readonly string[] = PEOPLE_FILTERS[key];
  return (typeof value === "string" && options.includes(value) ? value : DEFAULT_PEOPLE_SEARCH[key]) as Choice<K>;
}

export function parsePeopleSearch(raw: Readonly<Record<string, unknown>>): PeopleSearch {
  return { state: choice("state", raw.state), kind: choice("kind", raw.kind) };
}
