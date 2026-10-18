// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, stripSearchParams, useNavigate, type SearchSchemaInput } from "@tanstack/react-router";

import { listAgentsOptions } from "../api/@tanstack/react-query.gen";
import { AgentsList, NewAgent } from "../components/directory/AgentsList";
import { DEFAULT_SEARCH, parseAgentsSearch, type AgentsSearch } from "../components/directory/agent-search";
import { explain } from "../components/directory/errors";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";

// The filters live in the URL, so a link or the back button restores them (#333);
// a default is stripped, so the plain address is the plain list.
export const Route = createFileRoute("/agents")({
  validateSearch: (raw: Partial<AgentsSearch> & SearchSchemaInput) =>
    parseAgentsSearch(raw as Readonly<Record<string, unknown>>),
  search: { middlewares: [stripSearchParams(DEFAULT_SEARCH)] },
  component: AgentsRoute,
});

function AgentsRoute() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const query = useQuery({ ...listAgentsOptions({ query: search }), refetchInterval: 30_000 });
  return (
    <>
      <PageHeading
        title="Agent connections"
        lead="Connect an agent, verify its requests, and see where execution is governed."
        actions={<NewAgent />}
      />
      {query.data !== undefined ? (
        <AgentsList
          data={query.data}
          search={search}
          onSearch={(next) => {
            void navigate({ search: (previous) => ({ ...previous, ...next }) });
          }}
        />
      ) : query.error !== null ? (
        <EmptyState title="The agents could not be read.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the agents.</p>
      )}
    </>
  );
}
