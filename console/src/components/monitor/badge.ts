// SPDX-License-Identifier: AGPL-3.0-only
// The count beside Monitoring (#678): open findings while there are any, else the quiet sources
// and collections (stale sources plus overdue connections), and a link that lands on what it
// counts. The numbers are the shell's own counts, read from the tenant view an administrator's
// shell already holds, so the badge adds no request and polls nothing. Every page loads this
// module with the sidebar, so it is a pure function with nothing else in it.

import type { MonitorSearch } from "./search";

export interface MonitoringBadge {
  /** The number the link lands on; zero shows no pill. */
  count: number;
  search: MonitorSearch;
  /** The pill's accessible name: what it counts. */
  label: string;
}

/** "2 sources or collections quiet", or with a prefix "2 monitoring sources or collections quiet". */
const quietItems = (quiet: number, prefix = ""): string =>
  `${String(quiet)} ${prefix}${quiet === 1 ? "source or collection" : "sources or collections"} quiet`;

export function monitoringBadge(open: number, quiet: number): MonitoringBadge {
  if (open > 0) {
    const findings = `${String(open)} open finding${open === 1 ? "" : "s"}`;
    return { count: open, search: { view: "findings" }, label: quiet > 0 ? `${findings}; ${quietItems(quiet)}` : findings };
  }
  return quiet > 0
    ? { count: quiet, search: { focus: "quiet" }, label: quietItems(quiet, "monitoring ") }
    : { count: 0, search: {}, label: "" };
}
