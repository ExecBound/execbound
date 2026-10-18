// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { readApprovalCoverageOptions } from "../../api/@tanstack/react-query.gen";
import { can, useSession } from "../../lib/session";
import { COVERAGE_ID } from "./coverage-id";

/**
 * Under a review rule of the active policy, who can decide its action (#678): the Approval
 * rules page's coverage read, shared through its query and never polled. A session without
 * workspace-wide `access.manage` sees nothing and asks nothing.
 */
export function CoverageLine({ bundleId, action }: { bundleId: string; action: string }) {
  const session = useSession();
  const allowed = can(session, "access.manage");
  const coverage = useQuery({ ...readApprovalCoverageOptions(), enabled: allowed });
  if (!allowed || coverage.data === undefined) return null;
  const current = session.space?.id;
  const lines = coverage.data.spaces
    .filter((space) => space.bundle_id === bundleId && (current === undefined || space.space_id === current))
    .flatMap((space) => space.actions.filter((held) => held.action === action).map((held) => ({ space, held })));
  return (
    <>
      {lines.map(({ space, held }) => (
        <p key={space.space_id} className="note coverage-line">
          {held.reviewers} {held.reviewers === 1 ? "person" : "people"} can decide this in {space.name}
          {held.held_uncovered.total > 0
            ? ` · ${String(held.held_uncovered.total)} held ${held.held_uncovered.total === 1 ? "resource" : "resources"} cannot be decided`
            : null}
          {" · "}
          <Link to="/approvers" hash={COVERAGE_ID}>
            Approval rules
          </Link>
        </p>
      ))}
    </>
  );
}
