// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";

import { readAgentOptions } from "../api/@tanstack/react-query.gen";
import { AgentDetailView, parseAgentSection, type AgentSection } from "../components/directory/AgentDetail";
import { explain } from "../components/directory/errors";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { discoveredName, principalName } from "../components/directory/format";
import { titleNoun, titleNumber, usePageName, type PageName } from "../shell/page-name";
import type { AgentDetail } from "../api/types.gen";

export interface AgentSearch {
  section?: AgentSection;
}

/**
 * The section lives in the address, `?section=connection`, so a link, a reload and Back keep it
 * (#678). The route tree is in every page's first load, so the value is checked in the agent
 * page's own chunk (`parseAgentSection`), not here, and anything else is dropped there.
 */
export const Route = createFileRoute("/agents_/$agentId")({
  validateSearch: (search: Record<string, unknown>) => search as AgentSearch,
  component: AgentRoute,
});

/** The crumb is the name the page's heading prints; the title is "Agent 3" and never the label. */
function agentPageName(detail: AgentDetail | undefined): PageName {
  const agent = detail?.agent ?? null;
  const current =
    detail === undefined
      ? "Agent"
      : agent !== null
        ? principalName("Agent", agent.label, agent.number, detail.row_id)
        : discoveredName(detail.discovered?.agent.display_name, detail.row_id);
  return {
    crumbs: [{ label: "Agent connections", link: { to: "/agents" } }],
    current,
    title: [titleNumber("Agent", agent?.number) ?? titleNoun("Agent")],
  };
}

function AgentRoute() {
  const { agentId } = Route.useParams();
  const section = parseAgentSection(Route.useSearch());
  const navigate = useNavigate();
  const query = useQuery(readAgentOptions({ path: { row_id: agentId } }));
  const detail = query.data;
  usePageName(agentPageName(detail));
  // A bound agent's id answers with its principal's detail; the address follows (#228, step 2).
  useEffect(() => {
    if (detail !== undefined && detail.row_id !== agentId) {
      void navigate({ to: "/agents/$agentId", params: { agentId: detail.row_id }, search: (previous) => previous, replace: true });
    }
  }, [detail, agentId, navigate]);
  if (detail !== undefined) return <AgentDetailView detail={detail} section={section} />;
  return (
    <>
      <PageHeading title="Agent" />
      {query.error !== null ? (
        <EmptyState title="This agent could not be read.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the agent.</p>
      )}
    </>
  );
}
