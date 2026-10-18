// SPDX-License-Identifier: AGPL-3.0-only
import { Link, useRouterState } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";

import { useEdition } from "../edition/context";
import { can, useSession, type Mode } from "../lib/session";
import { Icon } from "./icons";
import { entryFor } from "./navigation";
import { usePageNameValue } from "./page-name";
import { SpaceSwitcher } from "./SpaceSwitcher";
import { WorkspaceSwitcher } from "./WorkspaceSwitcher";

// The disclosure for a long chain loads only where a page has one; until it has, every ancestor
// stays on screen. What the mode covers loads the first time someone opens it.
const MoreCrumbs = lazy(() => import("./MoreCrumbs"));
const Coverage = lazy(() => import("./Coverage"));

const MODES: Record<Mode, string> = {
  ENFORCE: "Enforcing",
  OBSERVE: "Observe only",
  UNKNOWN: "Mode",
};

export function TopBar({
  onAsk,
  onStop,
  onNotifications,
  onNavigate,
  sheetOpen = false,
  waiting = 0,
}: {
  /** Absent where the deployment configured no model, so the button is not there (#330). */
  onAsk?: () => void;
  onStop: () => void;
  onNotifications: () => void;
  onNavigate: () => void;
  /** Whether the navigation sheet Menu opens is open. */
  sheetOpen?: boolean;
  /** What waits on this person: their assigned approvals and, for an administrator, open findings. */
  waiting?: number;
}) {
  const [coverage, setCoverage] = useState(false);
  const session = useSession();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const { navigation, TopBarItems } = useEdition();
  const entry = entryFor(pathname, navigation, session.role, {
    assistant: session.assistant,
    invitations: session.invitations,
    permissions: session.permissions,
  });
  const name = usePageNameValue();
  const crumbs = name?.crumbs ?? [];
  return (
    <header className="topbar">
      <WorkspaceSwitcher />
      {/* The phone's switcher. The sidebar, and the one in it, are not on screen under
          768 px, and a person on a phone still has to read which space they are in and be
          able to leave it. Only one of the two is ever displayed. */}
      <SpaceSwitcher compact />
      <nav aria-label="Breadcrumb" className="crumbs">
        <ol>
          {/* The first crumb reads the space over the tenant, so a person never has to guess
              which tenant they are in or which space they are looking at. */}
          <li>
            {session.space === null ? session.tenant.name : `${session.space.name} · ${session.tenant.name}`}
          </li>
          {crumbs.length > 1 ? (
            <Suspense fallback={null}>
              <MoreCrumbs
                hidden={crumbs.slice(0, -1).map((crumb, index) => (
                  <Link key={index} {...crumb.link} activeOptions={{ exact: true }}>
                    {crumb.label}
                  </Link>
                ))}
              />
            </Suspense>
          ) : null}
          {crumbs.map((crumb, index) => (
            <li key={index} className={index < crumbs.length - 1 ? "crumb-middle" : undefined}>
              {/* An ancestor is never the current page, so it is never marked as one. */}
              <Link {...crumb.link} className="crumb-link" activeOptions={{ exact: true }}>
                {crumb.label}
              </Link>
            </li>
          ))}
          <li aria-current="page">{name?.current ?? entry?.label ?? "Console"}</li>
        </ol>
      </nav>
      <div className="topbar-actions">
        <button
          type="button"
          className="btn phone-navigation"
          onClick={onNavigate}
          aria-label="Navigation menu"
          aria-haspopup="dialog"
          aria-expanded={sheetOpen}
        >
          <Icon name="menu" />
          <span className="btn-label">Menu</span>
        </button>
        <details
          className="coverage-help"
          onToggle={(event) => {
            if (event.currentTarget.open) setCoverage(true);
          }}
        >
          <summary className={`mode mode-${session.mode.toLowerCase()}`}>
            {/* The word is its own span so a narrow phone can hide it visually and keep it
                as the summary's name; the dot alone still shows the mode's colour. */}
            <span className="mode-dot" aria-hidden="true" /><span className="mode-word">{MODES[session.mode]}</span><span className="sr-only">: protection coverage</span>
          </summary>
          {coverage ? (
            <Suspense fallback={null}>
              <Coverage mode={session.mode} />
            </Suspense>
          ) : null}
        </details>
        {can(session, "workspace.manage") ? (
          <button
            type="button"
            className={session.stop === null ? "btn btn-danger-outline" : "btn btn-danger"}
            onClick={onStop}
            aria-label="Emergency stop"
            title={session.stop === null ? "Activate the emergency stop" : "Stop active: open to resume"}
          >
            <Icon name="stop" />
            <span className="btn-label">Emergency stop</span>
          </button>
        ) : session.stop !== null ? (
          <span className="mode mode-stopped">
            <span className="mode-dot" aria-hidden="true" />
            Stop active
          </span>
        ) : null}
        {/* An edition's entries follow core's mode and emergency stop, as every slot follows
            core's own content, so no entry pushes the stop toward the right edge. They come
            before Ask, which they sit beside. */}
        <TopBarItems />
        {onAsk !== undefined ? (
          <button type="button" className="btn topbar-in-menu" onClick={onAsk} aria-label="Ask">
            <Icon name="ask" />
            <span className="btn-label">Ask</span>
          </button>
        ) : null}
        <button
          type="button"
          className="btn btn-icon bell"
          aria-label={waiting > 0 ? `Notifications, ${String(waiting)} waiting on you` : "Notifications"}
          onClick={onNotifications}
        >
          <Icon name="bell" />
          {waiting > 0 ? <span className="bell-dot" aria-hidden="true" /> : null}
        </button>
      </div>
    </header>
  );
}
