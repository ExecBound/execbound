// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, stripSearchParams, type SearchSchemaInput } from "@tanstack/react-router";

import { readApprovalOptions } from "../lib/shell-api";
import { RoutedApprovals } from "../approvals/RoutedApprovals";
import { titleNoun, titleRef, usePageName, type PageName } from "../shell/page-name";
import { DEFAULT_APPROVALS_SEARCH, parseApprovalsSearch, type ApprovalsSearch } from "../approvals/search";

// An approval opened from a link is its own route (#333): this chunk and what it
// imports are the whole page, so a cold link pays for nothing Home would have loaded.
export const Route = createFileRoute("/approvals/$approvalId")({
  validateSearch: (raw: ApprovalsSearch & SearchSchemaInput) => parseApprovalsSearch(raw),
  search: { middlewares: [stripSearchParams(DEFAULT_APPROVALS_SEARCH)] },
  component: ApprovalRoute,
});

/** Under Approvals, named by its request reference once the page has read it; never asked for. */
function approvalPageName(ref: string | undefined): PageName {
  return {
    crumbs: [{ label: "Approvals", link: { to: "/approvals" } }],
    current: ref ?? "Approval",
    title: [titleRef(ref) ?? titleNoun("Approval")],
  };
}

function ApprovalRoute() {
  const { approvalId } = Route.useParams();
  // Observes the page's own read and asks for nothing: naming the page costs no request.
  const approval = useQuery({ ...readApprovalOptions({ path: { approval_id: approvalId } }), enabled: false }).data;
  usePageName(approvalPageName(approval?.item.request_ref));
  return <RoutedApprovals selected={approvalId} />;
}
