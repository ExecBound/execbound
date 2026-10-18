// SPDX-License-Identifier: AGPL-3.0-only
// The Approvals page's view lives in the address (#678): Back, a reload and a shared link all
// return to the same chip. Anything but one of the four views is dropped, so the page falls
// back to Pending rather than to a view nobody asked for.

export type ApprovalsView = "pending" | "decided" | "lapsed" | "others";

export interface ApprovalsSearch {
  view?: ApprovalsView;
}

export const APPROVALS_VIEWS: readonly ApprovalsView[] = ["pending", "decided", "lapsed", "others"];

/** The default the address never shows: `stripSearchParams` removes it. */
export const DEFAULT_APPROVALS_SEARCH = { view: "pending" } as const;

/** The route's search parameters, read defensively. */
export function parseApprovalsSearch(raw: { readonly view?: unknown }): ApprovalsSearch {
  const view = APPROVALS_VIEWS.find((option) => option === raw.view);
  return view === undefined ? {} : { view };
}
