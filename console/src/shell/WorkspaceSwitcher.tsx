// SPDX-License-Identifier: AGPL-3.0-only
import { lazy, Suspense, useRef, useState } from "react";

import { useSession } from "../lib/session";
import { useWorkspaces, waitingElsewhere } from "../lib/workspaces";

// The menu is fetched the first time it opens, so the shell and a cold approval link carry
// only this trigger.
const WorkspaceMenu = lazy(() => import("./WorkspaceMenu"));

/**
 * The account's workspaces (#238, #678). A dot, and a phrase in the trigger's name, say when
 * approvals wait for this account in another workspace; the menu says how many and when the
 * first lapses. Only a count crosses from another workspace, and only where entering it asks
 * nothing more of this sign-in.
 */
export function WorkspaceSwitcher() {
  const session = useSession();
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const list = useWorkspaces();
  if (!session.canSwitchWorkspaces) return null;
  const waiting = waitingElsewhere(list.data?.workspaces ?? []);
  const phrase =
    waiting === 0 ? "" : waiting === 1 ? ", approvals waiting in another workspace" : `, approvals waiting in ${String(waiting)} other workspaces`;
  return (
    <div className="workspace-switcher">
      <button
        ref={trigger}
        type="button"
        className="btn"
        aria-label={`Workspace ${session.tenant.name}${phrase}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => {
          setOpen(!open);
        }}
      >
        Workspace<span className="workspace-current">{session.tenant.name}</span>
        {waiting > 0 ? <span className="workspace-dot" aria-hidden="true" /> : null}
      </button>
      {open ? (
        <Suspense fallback={null}>
          <WorkspaceMenu
            onClose={(focus) => {
              setOpen(false);
              if (focus) trigger.current?.focus();
            }}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
