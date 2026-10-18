// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense } from "react";

import { useEdition } from "../edition/context";
import { useSession } from "../lib/session";
import { Icon } from "./icons";
import { Mark } from "./Mark";
import { FOOTER, mainEntries, visible, type NavigationEntry } from "./navigation";
import { NavigationGroups, useNavigationItem } from "./NavigationList";
import { SignOut } from "./SignOut";
import { SpaceSwitcher } from "./SpaceSwitcher";

// Getting started's card reads the setup progress; it loads on demand, with the plain footer
// rows meanwhile, so the shell's first load does not carry it (#678).
const StartedFoot = lazy(() => import("./StartedCard"));

/** The pills' numbers, and Monitoring's quiet items, which its entry counts when nothing is open. */
export type Counts = Partial<Record<NonNullable<NavigationEntry["count"]> | "quiet", number>>;

export function Sidebar({ rail, onToggle, onSearch }: { rail: boolean; onToggle: () => void; onSearch: () => void }) {
  const session = useSession();
  // Ask exists only where the operator configured a model (#330); everything else is the
  // role's to see.
  const features = { assistant: session.assistant, invitations: session.invitations, permissions: session.permissions };
  // An edition's entries follow core's, each in its group (#496).
  const { navigation } = useEdition();
  const entries = visible(mainEntries(navigation), session.role, features);
  const footer = visible(FOOTER, session.role, features);
  // The card while setup steps are left; otherwise Getting started is an ordinary footer row.
  const started = footer.some((entry) => entry.to === "/welcome");

  const item = useNavigationItem({ rail });
  // Search is "Search or ask" only where the deployment has an assistant.
  const searchName = session.assistant ? "Search or ask" : "Search";

  const rows = <ul className="nav-list">{footer.map(item)}</ul>;

  return (
    <nav className="sidebar" aria-label="Main">
      <div className="sidebar-brand">
        <Mark size={24} />
        <span className="nav-label sidebar-brand-name">ExecBound</span>
      </div>
      {/* The tenant block became the space switcher: the
          space over the tenant, and the tenant name still on screen, because the tenant is
          the boundary and a space is ownership and view inside it. */}
      <SpaceSwitcher rail={rail} />
      <button type="button" className="search" onClick={onSearch} title={rail ? searchName : undefined}>
        <Icon name="search" />
        <span className="nav-label">{searchName}</span>
        <kbd className="nav-label">Ctrl K</kbd>
      </button>
      {/* The only part that scrolls, so the footer below stays in view (#678). */}
      <div className="sidebar-scroll">
        <NavigationGroups entries={entries} item={item} />
      </div>
      <div className="sidebar-foot">
        {started ? (
          <Suspense fallback={rows}>
            <StartedFoot rail={rail} entries={footer} item={item} />
          </Suspense>
        ) : (
          rows
        )}
        <button
          type="button"
          className="nav-link nav-toggle"
          onClick={onToggle}
          aria-pressed={rail}
          aria-label={rail ? "Expand the sidebar" : "Collapse the sidebar"}
        >
          <Icon name={rail ? "expand" : "collapse"} />
          <span className="nav-label">Collapse</span>
        </button>
        <div className="account">
          <span className="avatar" aria-hidden="true">
            {session.person.initials !== "" ? session.person.initials : initials(session.person.label)}
          </span>
          <span className="nav-label account-name">
            <strong title={session.person.label}>{session.person.label}</strong>
            {session.person.detail !== "" ? <small>{session.person.detail}</small> : null}
          </span>
          <SignOut className="nav-label account-out" />
        </div>
      </div>
    </nav>
  );
}

export function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter((part) => part !== "")
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}
