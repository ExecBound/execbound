// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import { useEdition } from "../edition/context";
import { useSession } from "../lib/session";
import type { Counts } from "./Sidebar";
import { Icon } from "./icons";
import { phoneTabs } from "./navigation";

/** On a phone the sidebar becomes a bottom tab bar (#333). */
export function TabBar({ counts = {} }: { counts?: Counts }) {
  const session = useSession();
  const { navigation } = useEdition();
  return (
    <nav className="tabbar" aria-label="Main, phone">
      <ul>
        {phoneTabs(session.role, { invitations: session.invitations, permissions: session.permissions }, navigation).map((entry) => {
          const count = entry.count === undefined ? undefined : counts[entry.count];
          return (
            <li key={entry.to}>
              <Link
                to={entry.to}
                className="tab"
                activeProps={{ className: "tab tab-active", "aria-current": "page" }}
                activeOptions={{ exact: entry.to === "/" }}
              >
                <span className="tab-icon">
                  <Icon name={entry.icon} size={20} />
                  {count !== undefined && count > 0 ? (
                    <span className="pill pill-tab" aria-label={`${String(count)} waiting`}>
                      {count}
                    </span>
                  ) : null}
                </span>
                <span>{entry.tabLabel ?? entry.label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
