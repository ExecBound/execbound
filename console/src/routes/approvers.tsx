// SPDX-License-Identifier: AGPL-3.0-only
import { createFileRoute } from "@tanstack/react-router";

import { ApprovalRules } from "../components/directory/ApprovalRules";
import { PageHeading } from "../components/ui/PageHeading";

export const Route = createFileRoute("/approvers")({
  component: ApproversRoute,
});

function ApproversRoute() {
  return (
    <>
      <PageHeading
        title="Approval rules"
        lead="Route requests to reviewer groups based on the action, resource and Space."
      />
      <ApprovalRules />
    </>
  );
}
