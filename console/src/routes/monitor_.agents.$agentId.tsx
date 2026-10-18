// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { readMonitorAgentOptions } from "../api/@tanstack/react-query.gen";
import { AgentDetailPage } from "../components/monitor/AgentDetailPage";
import { titleNoun, usePageName, type PageName } from "../shell/page-name";

/** A monitored agent: its directory display name is the crumb, never the title. */
function monitoredAgentPageName(displayName: string | undefined): PageName {
  return {
    crumbs: [
      { label: "Monitoring", link: { to: "/monitor" } },
      { label: "Monitored agents", link: { to: "/monitor", search: { view: "agents" } } },
    ],
    current: displayName ?? "Monitored agent",
    title: [titleNoun("Monitored agent")],
  };
}

/** One agent's page, beside the Monitoring entry rather than inside it, as `/monitor/agents/{id}` is today. */
export const Route = createFileRoute("/monitor_/agents/$agentId")({
  component: AgentRoute,
});

function AgentRoute() {
  const { agentId } = Route.useParams();
  const agent = useQuery({ ...readMonitorAgentOptions({ path: { agent_id: agentId } }), enabled: false }).data;
  usePageName(monitoredAgentPageName(agent?.agent.display_name));
  return <AgentDetailPage agentId={agentId} />;
}
