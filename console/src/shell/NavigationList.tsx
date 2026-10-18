// SPDX-License-Identifier: AGPL-3.0-only
// The navigation's rows and groups (#678), which the sidebar and the phone's navigation sheet both
// render, so the two lists can never differ. Each row's count pill is computed here from the
// shell's own counts, Monitoring's through its badge, rather than passed in by each caller, so the
// sheet's pills are always the sidebar's.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { monitoringBadge } from "../components/monitor/badge";
import { useSingleKeys } from "../lib/keys";
import { useCounts } from "./counts";
import { Icon } from "./icons";
import type { Group, NavigationEntry } from "./navigation";

const GROUPS: readonly Group[] = ["Agent security", "Team & access", "Visibility"];

/** How one row renders, for the lists and for the Getting started card's footer. */
export type ItemRenderer = (entry: NavigationEntry) => ReactNode;

/**
 * The row renderer. `rail` titles each link with its name, and its keys while single-key
 * shortcuts are on; `onChoose` runs when a row is chosen, as the sheet closes itself.
 */
export function useNavigationItem({ rail = false, onChoose }: { rail?: boolean; onChoose?: () => void } = {}): ItemRenderer {
  const counts = useCounts();
  const [single] = useSingleKeys();
  // Monitoring's pill counts open findings, else quiet sources and collections, and its link
  // lands on what it counts (#678); `counts.monitoring` keeps meaning open findings.
  const monitoring = monitoringBadge(counts.monitoring ?? 0, counts.quiet ?? 0);
  return (entry) => {
    const isMonitoring = entry.count === "monitoring";
    const count = isMonitoring ? monitoring.count : entry.count === undefined ? undefined : counts[entry.count];
    return (
      <li key={entry.to}>
        <Link
          to={entry.to}
          search={isMonitoring ? monitoring.search : undefined}
          className="nav-link"
          activeProps={{ className: "nav-link nav-link-active", "aria-current": "page" }}
          activeOptions={{ exact: entry.to === "/", includeSearch: !isMonitoring }}
          title={rail ? (single && entry.key !== undefined ? `${entry.label} (g ${entry.key})` : entry.label) : undefined}
          onClick={onChoose}
        >
          <Icon name={entry.icon} />
          <span className="nav-label">{entry.label}</span>
          {count !== undefined && count > 0 ? (
            <span className="pill" aria-label={isMonitoring ? monitoring.label : `${String(count)} waiting`}>
              {count}
            </span>
          ) : null}
        </Link>
      </li>
    );
  };
}

/** The main entries: those without a group first, then each group under its heading. */
export function NavigationGroups({ entries, item }: { entries: readonly NavigationEntry[]; item: ItemRenderer }) {
  return (
    <>
      <ul className="nav-list">{entries.filter((entry) => entry.group === undefined).map(item)}</ul>
      {GROUPS.map((group) => {
        const items = entries.filter((entry) => entry.group === group);
        if (items.length === 0) return null;
        return (
          <div key={group} className="nav-section">
            <p className="nav-group nav-label">{group}</p>
            <ul className="nav-list" aria-label={group}>
              {items.map(item)}
            </ul>
          </div>
        );
      })}
    </>
  );
}
