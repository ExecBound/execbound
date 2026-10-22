// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { listPolicyOptions, readPolicyBundleOptions } from "../api/@tanstack/react-query.gen";
import { explain } from "../components/directory/errors";
import { BundleList, NewDraft } from "../components/policy/BundleList";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { NoConnectionHint } from "../components/welcome/NoConnectionHint";
import { inAllSpaces, useSession } from "../lib/session";

export interface PolicySearch {
  /** Whether the retired versions are shown; `?retired=1` in the address, so Back keeps it. */
  retired?: 1;
}

export const Route = createFileRoute("/policy")({
  validateSearch: (search: Record<string, unknown>): PolicySearch =>
    search.retired === 1 || search.retired === "1" ? { retired: 1 } : {},
  component: PolicyRoute,
});

function PolicyRoute() {
  const search = Route.useSearch();
  const session = useSession();
  const query = useQuery(listPolicyOptions());
  const page = query.data;
  const active = useQuery({ ...readPolicyBundleOptions({ path: { bundle_id: page?.active ?? "" } }), enabled: page?.active != null });
  return (
    <>
      <PageHeading
        title="Policies"
        lead="Control what agents may do, what needs approval, and how many targets they may affect. Edit a draft, validate it, preview past decisions, then explicitly activate it."
      />
      {page !== undefined ? (
        <>
          <NewDraft hasActive={page.active !== null} formAvailable={active.data?.form_available ?? false} starterAvailable={page.starter_available} starterHint={page.starter_hint} />
          {!inAllSpaces(session) && page.active === null && !page.starter_available && session.role === "ADMIN" ? <NoConnectionHint /> : null}
          <BundleList page={page} showRetired={search.retired === 1} />
        </>
      ) : query.error !== null ? (
        <EmptyState title="The policy bundles could not be read.">
          {explain(query.error)}
        </EmptyState>
      ) : (
        <p role="status">Loading the policy bundles.</p>
      )}
    </>
  );
}
