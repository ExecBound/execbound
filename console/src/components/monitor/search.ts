// SPDX-License-Identifier: AGPL-3.0-only
// Monitoring's search values (#678): the one place each is checked against a fixed list or a
// pattern. The route's component calls `parseMonitorSearch`, and each view calls it or its
// patterns again; the route's validateSearch passes the values through unchecked, so that this
// module stays out of every page's first load. It is kept small and carries no copy.

import { isMonitorProvider, type MonitorProvider } from "./setup";

// The six views, in the page's order; their labels live in views.ts.
export const VIEWS = ["connections", "inventory", "agents", "activity", "findings", "alerts"] as const;
export type View = (typeof VIEWS)[number];
export const STATES = ["open", "acknowledged", "all"] as const;
export type FindingState = (typeof STATES)[number];
/** A canonical, lower-case UUID: the only form the server answers for. */
export const FINDING_ID = /^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/;
/** The pattern `create_source` holds a reporting source's story id to (monitoring/store.py):
 * letters, digits, `_`, `.`, `:` and `-`, 1 to 96 of them. */
export const STORY_ID = /^[\w.:-]{1,96}$/;

export interface MonitorSearch {
  view?: View;
  state?: FindingState;
  open?: string;
  story?: string;
  focus?: "quiet";
  /** The provider whose setup dialog opens on Connections (#678). */
  setup?: MonitorProvider;
  /** A return from Microsoft's admin consent: it says a return happened, and nothing more. */
  connect?: "done" | "refused";
}

/** Every monitoring search value, kept only when it is one the page knows. A digit-only story
 * id is written by the router as a quoted string, which reads back as the same string. */
export function parseMonitorSearch({ view, state, open, story, focus, setup, connect }: Record<string, unknown>): MonitorSearch {
  return {
    ...(VIEWS.includes(view as View) && { view: view as View }),
    ...(STATES.includes(state as FindingState) && { state: state as FindingState }),
    ...(typeof open === "string" && FINDING_ID.test(open) && { open }),
    ...(typeof story === "string" && STORY_ID.test(story) && { story }),
    ...(focus === "quiet" && { focus }),
    ...(isMonitorProvider(setup) && { setup }),
    ...((connect === "done" || connect === "refused") && { connect }),
  };
}
