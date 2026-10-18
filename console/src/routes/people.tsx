// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, stripSearchParams, useNavigate, type SearchSchemaInput } from "@tanstack/react-router";

import { listPeopleOptions } from "../api/@tanstack/react-query.gen";
import { explain } from "../components/directory/errors";
import { InviteTeammate } from "../components/directory/InviteTeammate";
import { NewApprover, PeopleList } from "../components/directory/PeopleList";
import { DEFAULT_PEOPLE_SEARCH, parsePeopleSearch, type PeopleSearch } from "../components/directory/people-search";
import { TeammateInvitations } from "../components/directory/TeammateInvitations";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { can, useSession } from "../lib/session";

export const Route = createFileRoute("/people")({
  validateSearch: (raw: Partial<PeopleSearch> & SearchSchemaInput) =>
    parsePeopleSearch(raw as Readonly<Record<string, unknown>>),
  search: { middlewares: [stripSearchParams(DEFAULT_PEOPLE_SEARCH)] },
  component: PeopleRoute,
});

function PeopleRoute() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const session = useSession();
  const canInvite = can(session, "access.manage");
  // An invitation is an email: without a relay it would wait for one that never comes.
  const canEmail = canInvite && session.mail;
  const query = useQuery({ ...listPeopleOptions({ query: search }), refetchInterval: 30_000 });
  return (
    <>
      <PageHeading
        title="Users"
        lead="Manage user accounts, sign-in and access roles."
        actions={
          <>
            <NewApprover />
            {canEmail ? <InviteTeammate /> : null}
          </>
        }
      />
      {canInvite && !session.mail ? (
        <p className="note">
          Inviting a teammate by email needs a mail relay, and this deployment has none. Add a{" "}
          <code>mail</code> block to the runtime configuration, or use Add user and help them set a
          password.
        </p>
      ) : null}
      {query.data !== undefined ? (
        <PeopleList
          data={query.data}
          search={search}
          onSearch={(next) => {
            void navigate({ search: (previous) => ({ ...previous, ...next }) });
          }}
        />
      ) : query.error !== null ? (
        <EmptyState title="Users could not be loaded.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading users.</p>
      )}
      {canInvite ? <TeammateInvitations /> : null}
    </>
  );
}
