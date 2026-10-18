// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, useNavigate } from "@tanstack/react-router";

import { MonitorPage } from "../components/monitor/MonitorPage";
import { parseMonitorSearch, type MonitorSearch } from "../components/monitor/search";

/**
 * `?view=` names the view; absent or not a view, the page shows Connections and the address
 * stays as typed. `state`, `open`, `story` and `focus` are each checked against a fixed list or
 * pattern by `parseMonitorSearch`, here in the route's component and again in each view, never
 * in `validateSearch`: the route tree is in every page's first load, an approval link opened
 * cold included, and the checks belong to the Monitoring chunk. The search type is therefore
 * unchecked, and nothing reads `Route.useSearch()` except through `parseMonitorSearch`.
 */
export const Route = createFileRoute("/monitor")({
  validateSearch: (search: Record<string, unknown>) => search as MonitorSearch,
  component: MonitorRoute,
});

function MonitorRoute() {
  const search = parseMonitorSearch(Route.useSearch());
  const navigate = useNavigate({ from: "/monitor" });
  return (
    <MonitorPage
      {...search}
      onSetupClosed={() => {
        // Closing the dialog takes `setup` out of the address, so a reload does not reopen it.
        void navigate({ search: (previous) => ({ ...previous, setup: undefined }), replace: true });
      }}
      onConnectRead={() => {
        // A return from Microsoft is read once; a reload does not say it again.
        void navigate({ search: (previous) => ({ ...previous, connect: undefined }), replace: true });
      }}
    />
  );
}
