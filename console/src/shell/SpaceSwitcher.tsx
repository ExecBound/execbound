// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useRef, useState } from "react";

import { useSession } from "../lib/session";
import { Icon } from "./icons";

// The create dialog is fetched the first time an administrator opens it, so Base UI's dialog
// and the spaces forms stay out of the shell's chunk on every page that never opens one.
const NewSpaceDialog = lazy(() => import("../components/spaces/NewSpaceDialog"));
// The listbox is fetched the first time it opens, as the workspace menu is, so the shell and a
// cold approval link carry only the trigger.
const SpaceMenu = lazy(() => import("./SpaceMenu"));

/** The option id of "All spaces"; a real space is keyed by its own id. */
export const ALL = "all";

/** The initials the rail's square carries: the first letters of up to two words. */
export function initialsOf(name: string): string {
  return name
    .split(/\s+/)
    .filter((part) => part !== "")
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

/**
 * The sidebar's space switcher. The tenant block became this:
 * the **space** name in the strong line and **the tenant name in the detail slot**, so the
 * security boundary is readable on every screen at all times — a space is ownership and view
 * inside a tenant and never a boundary of its own.
 *
 * It is a `<button>` and never a link, and the popover it opens is rendered inside the sidebar
 * with no portal and no new dependency: `tests/test_browser_console.py` asserts that the main
 * navigation's links equal its entry list in order, which a link here would break. The popover
 * is in the document only while it is open, and it carries no entrance animation, so the
 * browser suite's readiness gate never waits on it.
 *
 * `compact` is the phone's copy, in the top bar: the sidebar is not on screen under 768 px,
 * and a person on a phone still has to be able to see which space they are in and leave it.
 * Only one of the two is ever displayed, exactly as the sidebar and the tab bar are.
 */
export function SpaceSwitcher({ rail = false, compact = false }: { rail?: boolean; compact?: boolean }) {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const many = session.spaces > 1 || session.allSpaces;
  // Something to do: more than one space to move between, or an administrator who may make
  // one. A lone approver in a single space keeps the quiet block the tenant block was.
  const live = many || session.role === "ADMIN";
  const name = session.space?.name ?? "All spaces";
  const label = live
    ? `Space ${name} in ${session.tenant.name}; change space`
    : `Space ${name} in ${session.tenant.name}`;
  const close = (focus = true) => {
    setOpen(false);
    if (focus) trigger.current?.focus();
  };
  return (
    <div className={compact ? "switcher switcher-compact" : "switcher"}>
      <button
        ref={trigger}
        type="button"
        className={compact ? "tenant tenant-compact" : "tenant"}
        aria-label={label}
        aria-haspopup={live ? "listbox" : undefined}
        aria-expanded={live ? open : undefined}
        aria-disabled={live ? undefined : "true"}
        title={rail || compact ? `${name} — ${session.tenant.name}` : undefined}
        onClick={() => {
          if (live) setOpen((was) => !was);
        }}
      >
        <span className="tenant-mark" aria-hidden="true">
          {initialsOf(name)}
        </span>
        <span className="nav-label tenant-name">
          <strong>{name}</strong>
          <small>{session.tenant.name}</small>
        </span>
        {live ? <Icon name="chevron" size={16} className="nav-label tenant-chevron" /> : null}
      </button>
      {open ? (
        <Suspense fallback={null}>
          <SpaceMenu
            onClose={close}
            onCreate={() => {
              close(false);
              setCreating(true);
            }}
          />
        </Suspense>
      ) : null}
      {creating ? (
        <Suspense fallback={null}>
          <NewSpaceDialog
            open
            onClose={() => {
              setCreating(false);
              trigger.current?.focus();
            }}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
