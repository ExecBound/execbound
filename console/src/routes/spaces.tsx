// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, stripSearchParams, useNavigate, type SearchSchemaInput } from "@tanstack/react-router";
import { useState } from "react";

import NewSpaceDialog from "../components/spaces/NewSpaceDialog";
import { SpacePanel } from "../components/spaces/SpacePanel";
import { SpacesList } from "../components/spaces/SpacesList";
import { DEFAULT_SPACES_SEARCH, parseSpacesSearch, type SpacesSearch } from "../components/spaces/spaces-search";
import { Button } from "../components/ui/Button";
import { PageHeading } from "../components/ui/PageHeading";
import { useSession } from "../lib/session";
import { useCommand } from "../lib/commands";

export const Route = createFileRoute("/spaces")({
  validateSearch: (raw: Partial<SpacesSearch> & SearchSchemaInput) =>
    parseSpacesSearch(raw as Readonly<Record<string, unknown>>),
  search: { middlewares: [stripSearchParams(DEFAULT_SPACES_SEARCH)] },
  component: SpacesRoute,
});

/**
 * Spaces: the list, and one space's detail beside it with its members table.
 * Create lives in the sidebar switcher and is offered here too, because this is where
 * somebody who came looking for it will be.
 */
function SpacesRoute() {
  const session = useSession();
  const navigate = useNavigate({ from: Route.fullPath });
  const search = Route.useSearch();
  const [creating, setCreating] = useState(false);
  // The palette's New space opens the dialog as the button would (#678).
  useCommand("new-space", () => {
    if (session.role === "ADMIN") setCreating(true);
  });
  const onSearch = (next: Partial<SpacesSearch>) => {
    void navigate({ search: (previous) => ({ ...previous, ...next }) });
  };
  return (
    <>
      <PageHeading
        title="Spaces"
        lead="A space divides ownership and view inside this tenant: its own agents, connector accounts, policy selection, approvals and monitoring. The tenant stays the security boundary — a space is not isolation."
        actions={
          session.role === "ADMIN" ? (
            <Button
              variant="primary"
              onClick={() => {
                setCreating(true);
              }}
            >
              New space
            </Button>
          ) : undefined
        }
      />
      <div className="spaces">
        <SpacesList search={search} onSearch={onSearch} />
        {search.open !== undefined ? (
          <SpacePanel
            spaceId={search.open}
            onGone={() => {
              // Closing the detail drops `open` and keeps the filter the person set.
              void navigate({ search: (previous) => ({ q: previous.q, state: previous.state }) });
            }}
          />
        ) : null}
      </div>
      {creating ? (
        <NewSpaceDialog
          open
          onClose={() => {
            setCreating(false);
          }}
          onCreated={(spaceId) => {
            onSearch({ open: spaceId });
          }}
        />
      ) : null}
    </>
  );
}
