// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readMonitorOptions, readTenantOptions } from "../../api/@tanstack/react-query.gen";
import { useSession } from "../../lib/session";
import { PageHeading } from "../ui/PageHeading";
import { Activity } from "./Activity";
import { Agents } from "./Agents";
import { Alerts } from "./Alerts";
import { Connections } from "./Connections";
import { Findings } from "./Findings";
import { Inventory } from "./Inventory";
import type { MonitorSearch } from "./search";
import type { MonitorProvider } from "./setup";
import { INTRODUCTIONS, VIEW_LABELS, VIEWS, type View } from "./views";
import "./monitor.css";

/**
 * How long the tenant read stays fresh: the shell's `TENANT_STALE_MS`, written out because
 * importing the shell's counts here splits the shared poll timer into a chunk of its own that
 * every page's first load then fetches. A test holds the two equal.
 */
export const TABS_STALE_MS = 60_000;

/** Open findings and quiet items, from the tenant view the shell already holds, with its options. */
function useMonitoringCounts(): { open: number; quiet: number } {
  const session = useSession();
  const tenant = useQuery({
    ...readTenantOptions(),
    enabled: session.role === "ADMIN",
    refetchInterval: false,
    staleTime: TABS_STALE_MS,
  });
  const monitoring = tenant.data?.monitoring;
  return monitoring === undefined ? { open: 0, quiet: 0 } : { open: monitoring.open_findings, quiet: monitoring.stale + monitoring.overdue };
}

/**
 * Monitoring (#333): the six views `/monitor/{view}` serves today, under one
 * heading with a tab strip whose state is the `view` search parameter, so a link or the back
 * button restores it. Everything shown is source-reported or collected metadata; the page says
 * so where the Jinja page says so, and never calls a reported effect verified. The Findings tab
 * carries the open count and the Connections tab the quiet count (#678), read from the tenant
 * view the sidebar already holds.
 */
export function MonitorPage({
  view = "connections",
  state,
  open,
  story,
  focus,
  setup,
  onSetupClosed,
  connect,
  onConnectRead,
}: MonitorSearch & { onSetupClosed?: () => void; onConnectRead?: () => void }) {
  const counts = useMonitoringCounts();
  const pill: Partial<Record<View, [number, string]>> = {
    findings: [counts.open, "open"],
    connections: [counts.quiet, "quiet"],
  };
  return (
    <>
      <PageHeading title="Monitoring" lead={INTRODUCTIONS[view]} />
      <nav className="tabs" aria-label="Monitoring views">
        <ul>
          {VIEWS.map((entry) => {
            const [n, word] = pill[entry] ?? [0, ""];
            return (
              <li key={entry}>
                <Link
                  to="/monitor"
                  search={entry === "connections" ? {} : { view: entry }}
                  className="tab-link"
                  activeOptions={{ exact: true }}
                  aria-current={entry === view ? "page" : undefined}
                  aria-label={n > 0 ? `${VIEW_LABELS[entry]}, ${String(n)} ${word}` : undefined}
                >
                  {VIEW_LABELS[entry]}
                  {n > 0 ? (
                    <span className="pill" aria-hidden="true">
                      {n}
                    </span>
                  ) : null}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      {view === "agents" ? (
        <Agents />
      ) : view === "findings" ? (
        <Findings state={state} open={open} />
      ) : (
        <Snapshot
          view={view}
          story={story}
          focus={focus}
          setup={view === "connections" ? setup : undefined}
          onSetupClosed={onSetupClosed}
          connect={view === "connections" ? connect : undefined}
          onConnectRead={onConnectRead}
        />
      )}
    </>
  );
}

function Snapshot({
  view,
  story,
  focus,
  setup,
  onSetupClosed,
  connect,
  onConnectRead,
}: {
  view: Exclude<View, "agents" | "findings">;
  story?: string;
  focus?: "quiet";
  setup?: MonitorProvider;
  onSetupClosed?: () => void;
  connect?: "done" | "refused";
  onConnectRead?: () => void;
}) {
  const query = useQuery({
    ...readMonitorOptions(),
    refetchInterval: 30_000,
    throwOnError: (_error, failed) => failed.state.data === undefined,
  });
  const data = query.data;
  if (data === undefined) {
    return (
      <p className="muted" role="status">
        Loading monitoring
      </p>
    );
  }
  switch (view) {
    case "connections":
      return <Connections data={data} focus={focus} setup={setup} onSetupClosed={onSetupClosed} connect={connect} onConnectRead={onConnectRead} />;
    case "inventory":
      return <Inventory data={data} story={story} />;
    case "activity":
      return <Activity data={data} />;
    case "alerts":
      return <Alerts data={data} />;
  }
}
