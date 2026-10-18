// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { readPersonOptions } from "../api/@tanstack/react-query.gen";
import { explain } from "../components/directory/errors";
import { PersonDetailView } from "../components/directory/PersonDetail";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { principalName } from "../components/directory/format";
import { titleNoun, titleNumber, usePageName, type PageName } from "../shell/page-name";
import type { PersonDetail } from "../api/types.gen";

export const Route = createFileRoute("/people_/$personId")({
  component: PersonRoute,
});

/** The crumb is the name the page's heading prints; the title is "User 3" and never the label or email. */
function personPageName(detail: PersonDetail | undefined): PageName {
  const person = detail?.person;
  return {
    crumbs: [{ label: "Users", link: { to: "/people" } }],
    current:
      detail === undefined || person === undefined
        ? "User"
        : principalName("User", person.label, person.number, person.principal_id, detail.sign_in.email),
    title: [titleNumber("User", person?.number) ?? titleNoun("User")],
  };
}

function PersonRoute() {
  const { personId } = Route.useParams();
  const query = useQuery(readPersonOptions({ path: { principal_id: personId } }));
  usePageName(personPageName(query.data));
  if (query.data !== undefined) return <PersonDetailView detail={query.data} />;
  return (
    <>
      <PageHeading title="User" />
      {query.error !== null ? (
        <EmptyState title="This user could not be loaded.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the user.</p>
      )}
    </>
  );
}
