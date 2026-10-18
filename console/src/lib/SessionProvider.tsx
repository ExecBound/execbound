// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useEffect, useLayoutEffect, useRef, useSyncExternalStore, type ReactNode } from "react";

import { readSessionOptions, readWorkspacesQueryKey } from "./shell-api";
import type { ServiceLinksView, SessionView } from "../api/types.gen";
import { refName } from "../components/directory/handles";
import { forgetCsrfToken, holdCsrfToken } from "./client-config";
import { NO_SERVICE, SessionContext, type SessionSummary } from "./session";
import {
  announceEntered,
  holdWorkspace,
  staleReason,
  subscribeWorkspace,
  watchWorkspaceChanges,
  workspaceStale,
} from "./workspace-context";
import { removeFrame } from "./frame";

// What a tab left behind says loads only when a tab is left behind. A release that replaced the
// file since this tab loaded still gets the words, without the names.
const StalePage = lazy(() =>
  import("./StalePage").catch(() => ({
    default: () => (
      <main id="main">
        <h1>Workspace changed</h1>
        <a className="btn" href="/">Open Home</a>
      </main>
    ),
  })),
);

const MODES = { ENFORCE: "ENFORCE", OBSERVE: "OBSERVE" } as const;

/**
 * The plugin features the view names, or none where it names no list at all: an open tab can
 * outlive a deploy, and a server rolled back to before the list existed sends none. Without the
 * default, the first reader of the list, the command palette among them, throws, and the shell
 * falls to its error page.
 */
function featuresOf(view: SessionView): readonly string[] {
  const { features } = view as Omit<SessionView, "features"> & { features?: readonly string[] };
  return features ?? [];
}

/**
 * The deployment's service links, or none where the view names none: a server rolled back to
 * before they existed sends no `service`, and every link then stays hidden rather than the
 * shell failing on the first one it reads. A link an older server does not name, such as
 * `source_url`, reads as `null` for the same reason.
 */
function serviceOf(view: SessionView): ServiceLinksView {
  const { service } = view as Omit<SessionView, "service"> & { service?: Partial<ServiceLinksView> };
  return { ...NO_SERVICE, ...service };
}

/** The session view as the shell reads it: role, mode, tenant, space and person. */
export function summarise(view: SessionView): SessionSummary {
  const label = view.identity.label;
  const permissions = view.space === null ? view.access.permissions : (view.access.space_permissions[view.space.space_id] ?? []);
  const roleNames: Record<string, string> = { administrator: "Administrator", policy_manager: "Policy manager", approver: "Approver", viewer: "Viewer" };
  return {
    role: view.identity.kind === "ADMIN" ? "ADMIN" : permissions.includes("policy.manage") ? "POLICY_MANAGER" : permissions.includes("approvals.decide") ? "APPROVER" : "VIEWER",
    permissions,
    permissionsAnywhere: view.access.permissions,
    mode: MODES[view.tenant.mode],
    tenant: { id: view.tenant.tenant_id, name: view.tenant.name, detail: "" },
    canSwitchWorkspaces: view.can_switch_workspaces,
    // The space the session is looking at, kept rather than dropped: the switcher reads the
    // space over the tenant, and the tenant takes the detail slot under it, so the security
    // boundary is readable on every screen at all times.
    space:
      view.space === null
        ? null
        : { id: view.space.space_id, name: view.space.name, archived: view.space.archived },
    spaces: view.spaces,
    allSpaces: view.all_spaces,
    person: {
      label,
      detail: view.access.roles.map((role) => roleNames[role] ?? role).join(", "),
      initials: "",
      id: view.identity.principal_id,
    },
    stop:
      view.stop === null
        ? null
        : {
            at: view.stop.stopped_at,
            by: view.stop.stopped_by,
            reason: view.stop.reason,
            byName: view.stop.stopped_by_ref === null ? null : refName(view.stop.stopped_by_ref, "ADMIN"),
          },
    assistant: view.assistant,
    invitations: view.invitations,
    mail: view.mail,
    features: featuresOf(view),
    service: serviceOf(view),
    endsAt: view.ends_at,
    endReason: view.end_reason,
    csrf: view.csrf_token,
  };
}

/**
 * Load the session before mounting controls, and install its CSRF token before they paint.
 * A fast approval detail must not become actionable while the session request is still loading.
 * The server remains the authority; this only prevents an empty-token first mutation.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const reason = useSyncExternalStore(subscribeWorkspace, staleReason);
  const changed = reason !== null;
  const query = useQuery({ ...readSessionOptions(), refetchInterval: 60_000, staleTime: 30_000, enabled: !changed });
  const view = query.data;
  useEffect(watchWorkspaceChanges, []);
  useLayoutEffect(() => {
    if (view !== undefined) {
      const workspace = { id: view.tenant.tenant_id, name: view.tenant.name };
      holdWorkspace(view.generation, workspace);
      if (!workspaceStale()) {
        holdCsrfToken(view.csrf_token);
        announceEntered(view.generation, workspace);
      }
    }
  }, [view]);
  // The workspace list is read again with the session, never on a timer of its own, so it is
  // never read in a hidden tab; the first read of the session is not a refetch.
  const updated = query.dataUpdatedAt;
  const first = useRef(0);
  useEffect(() => {
    if (updated === 0) return;
    if (first.current === 0) first.current = updated;
    else if (updated !== first.current) {
      void client.invalidateQueries({ queryKey: readWorkspacesQueryKey(), refetchType: "active" }, { cancelRefetch: false });
    }
  }, [updated, client]);
  // The plain frame stays while the session is read, and goes the moment there is anything else
  // to show, before that is painted.
  const failed = query.isError;
  useLayoutEffect(() => {
    if (view !== undefined || failed || changed) removeFrame();
  }, [view, failed, changed]);
  useEffect(() => {
    if (changed) {
      forgetCsrfToken();
      void client.cancelQueries();
      client.clear();
    }
  }, [changed, client]);
  if (reason !== null) return <Suspense fallback={null}><StalePage reason={reason} /></Suspense>;
  if (view === undefined) {
    // While loading, the plain frame's own "Loading" is what shows. A failed read is said in the
    // frame's own styling, since the shell needs the session to draw.
    if (!failed) return null;
    return (
      <div className="frame">
        <aside className="frame-side" />
        <header className="frame-top" />
        <main id="main" className="frame-main">
          <h1>Your session could not be loaded.</h1>
          <button type="button" className="btn" onClick={() => { void query.refetch(); }}>Try again</button>
        </main>
      </div>
    );
  }
  // The cookie may have changed after the server served this notification URL.
  // Never mount detail queries until the selected workspace matches the link.
  const reviewWorkspace = /^\/workspaces\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\/approvals\//.exec(window.location.pathname)?.[1];
  if (reviewWorkspace !== undefined && reviewWorkspace !== view.tenant.tenant_id) {
    return <main id="main"><h1>Open review workspace</h1><p>You are in {view.tenant.name}. This request belongs to another workspace. Continue to select it.</p><a className="btn" href={window.location.pathname}>Open review workspace</a></main>;
  }
  return (
    <SessionContext.Provider value={summarise(view)}>
      {children}
    </SessionContext.Provider>
  );
}

