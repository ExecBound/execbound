// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";

import { listPolicyOptions, readPolicyBundleOptions } from "../api/@tanstack/react-query.gen";
import { explain } from "../components/directory/errors";
import { BundleDetailView } from "../components/policy/BundleDetail";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeading } from "../components/ui/PageHeading";
import { policyName } from "../components/policy/format";
import { titleShort, usePageName, type PageName } from "../shell/page-name";

export const Route = createFileRoute("/policy_/$bundleId")({
  component: BundleRoute,
});

function bundlePageName(bundleId: string): PageName {
  const short = titleShort("Policy version", bundleId);
  return {
    crumbs: [{ label: "Policies", link: { to: "/policy" } }],
    current: policyName(bundleId),
    title: short === undefined ? [] : [short],
  };
}

function BundleRoute() {
  const { bundleId } = Route.useParams();
  usePageName(bundlePageName(bundleId));
  const query = useQuery(readPolicyBundleOptions({ path: { bundle_id: bundleId } }));
  // The list says which bundle is the selection, so activation can name the one it retires.
  const listed = useQuery(listPolicyOptions());
  const detail = query.data;
  if (detail !== undefined) {
    const active = listed.data?.active ?? null;
    return (
      <BundleDetailView
        detail={detail}
        active={active === null ? null : { bundle_id: active }}
      />
    );
  }
  return (
    <>
      <PageHeading title="Bundle" />
      {query.error !== null ? (
        <EmptyState title="This bundle could not be read.">{explain(query.error)}</EmptyState>
      ) : (
        <p role="status">Loading the bundle.</p>
      )}
    </>
  );
}
