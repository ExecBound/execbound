// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute, stripSearchParams, type SearchSchemaInput } from "@tanstack/react-router";

import { RoutedApprovals } from "../approvals/RoutedApprovals";
import { DEFAULT_APPROVALS_SEARCH, parseApprovalsSearch, type ApprovalsSearch } from "../approvals/search";

export const Route = createFileRoute("/approvals/")({
  validateSearch: (raw: ApprovalsSearch & SearchSchemaInput) => parseApprovalsSearch(raw),
  search: { middlewares: [stripSearchParams(DEFAULT_APPROVALS_SEARCH)] },
  component: () => <RoutedApprovals />,
});
