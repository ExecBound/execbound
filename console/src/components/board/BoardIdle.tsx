// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";

import type { BoardView } from "../../api/types.gen";
import { EmptyState } from "../ui/EmptyState";
import { periodLabel } from "./search";

/** A quiet window says what is known, and gives a useful next step without inventing activity. */
export function BoardIdle({ view, canManage, canReview }: {
  view: BoardView;
  canManage: boolean;
  canReview: boolean;
}) {
  const hasHistory = view.last_request_seconds !== null;
  return (
    <EmptyState title={`No requests in the ${periodLabel(view.window_seconds).toLowerCase()}.`}>
      <p>
        {hasHistory
          ? "Earlier requests are still available. Choose a wider historical window or browse Activity to inspect them."
          : "No request has been recorded in your current view. Activity will appear when an agent sends a request through ExecBound."}
      </p>
      <p>A quiet board does not establish that connected systems are idle or that every action is governed.</p>
      <div className="board-next-actions">
        <Link className="btn btn-small" to="/activity">Browse requests</Link>
        {canReview ? <Link className="btn btn-small" to="/approvals">Open approvals</Link> : null}
        {!hasHistory && canManage ? <Link className="btn btn-small" to="/agents">Connect an agent</Link> : null}
      </div>
    </EmptyState>
  );
}
