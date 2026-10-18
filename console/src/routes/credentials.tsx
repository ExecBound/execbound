// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { listCredentialsOptions } from "../api/@tanstack/react-query.gen";
import { CredentialsList, IssueCredential } from "../components/directory/CredentialsList";
import { explain } from "../components/directory/errors";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";

export const Route = createFileRoute("/credentials")({
  component: CredentialsRoute,
});

function CredentialsRoute() {
  const query = useQuery({ ...listCredentialsOptions(), refetchInterval: 30_000 });
  return (
    <>
      <PageHeading
        title="API keys"
        lead="The keys your agents use to call ExecBound's API. People sign in under Team & access instead."
        actions={query.data !== undefined ? <IssueCredential data={query.data} /> : undefined}
      />
      {query.data !== undefined ? (
        <CredentialsList data={query.data} />
      ) : query.error !== null ? (
        <EmptyState title="The API keys could not be read.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the API keys.</p>
      )}
    </>
  );
}
