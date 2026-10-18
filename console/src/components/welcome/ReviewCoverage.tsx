// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { lazy, Suspense, useState } from "react";

import { listApproverScopesOptions, readApprovalCoverageOptions } from "../../api/@tanstack/react-query.gen";
import type { ApproversPage, CoverageAction } from "../../api/types.gen";
import { can, useSession } from "../../lib/session";
import { COVERAGE_ID } from "../directory/coverage-id";
import { Button } from "../ui/Button";

// The assignment dialog is the Approval rules page's own, fetched the first time it opens.
const AssignScope = lazy(() => import("../directory/ApproversList").then((module) => ({ default: module.AssignScope })));

const HEADING = "review-coverage-heading";

/** Which dialog is open: the action it is prefilled with, and whether with the reader. */
interface Opened {
  action: string;
  me: boolean;
}

/**
 * Which actions nobody in this Space can review (#678, A7 part 2), under the "Choose who can
 * review" milestone. It reads the Approval rules page's decision coverage (`GET
 * /approval-coverage`) and lists, by the catalog's words and never by a target, each action this
 * Space's active policy can hold that nobody can decide. Each fix opens that page's prefilled
 * assignment dialog, which assigns nothing until it is confirmed, stepped up and answered.
 * Nothing is assigned automatically.
 *
 * A session without `access.manage` asks nothing; the read itself needs workspace-wide
 * `access.manage`, and a refusal or a failure shows nothing more than the milestone sentence.
 */
export function ReviewCoverage({ spaceId }: { spaceId: string }) {
  const session = useSession();
  const allowed = can(session, "access.manage");
  const coverage = useQuery({ ...readApprovalCoverageOptions(), enabled: allowed });
  const space = coverage.data?.spaces.find((row) => row.space_id === spaceId);
  const rows = space === undefined || space.policy === "none" ? [] : space.actions.filter((row) => row.reviewers === 0);
  const fixable = rows.some((row) => row.known);
  const scopes = useQuery({ ...listApproverScopesOptions(), enabled: allowed && fixable });
  const [opened, setOpened] = useState<Opened | null>(null);
  if (!allowed || rows.length === 0) return null;
  const me = session.person.id;
  const mayHold = me !== undefined && scopes.data?.approvers.some((row) => row.principal_id === me) === true;
  return (
    <section className="review-coverage" aria-labelledby={HEADING}>
      <h3 id={HEADING}>Actions nobody in this Space can review</h3>
      <ul className="review-coverage-rows">
        {rows.map((row) => (
          <ActionRow
            key={row.action}
            row={row}
            ready={scopes.data !== undefined}
            mayHold={mayHold}
            onOpen={(choice) => {
              setOpened(choice);
            }}
          />
        ))}
      </ul>
      <p className="note">
        Nothing is assigned until you confirm it. For each resource and rule, see{" "}
        <Link to="/approvers" hash={COVERAGE_ID}>
          decision coverage
        </Link>
        .
      </p>
      {opened !== null && scopes.data !== undefined ? (
        <Suspense fallback={null}>
          <AssignScope
            key={`${opened.action}-${String(opened.me)}`}
            data={opened.me && me !== undefined ? first(scopes.data, me) : scopes.data}
            preset={{ action: opened.action }}
            open
            onOpenChange={(open) => {
              if (!open) setOpened(null);
            }}
          />
        </Suspense>
      ) : null}
    </section>
  );
}

/** The approvers with the reader first, so the dialog opens with them chosen. */
function first(data: ApproversPage, me: string): ApproversPage {
  const mine = data.approvers.filter((row) => row.principal_id === me);
  return { ...data, approvers: [...mine, ...data.approvers.filter((row) => row.principal_id !== me)] };
}

function ActionRow({
  row,
  ready,
  mayHold,
  onOpen,
}: {
  row: CoverageAction;
  ready: boolean;
  mayHold: boolean;
  onOpen: (opened: Opened) => void;
}) {
  return (
    <li className="review-coverage-row">
      <strong>
        <bdi>{row.action_label}</bdi>
      </strong>
      {!row.known ? (
        <span className="muted">Coverage unknown for this policy</span>
      ) : ready ? (
        <span className="review-coverage-fixes">
          <Button
            size="small"
            aria-label={`Add a reviewer for ${row.action_label}`}
            onClick={() => {
              onOpen({ action: row.action, me: false });
            }}
          >
            Add a reviewer
          </Button>
          {mayHold ? (
            <Button
              size="small"
              aria-label={`Assign me to review ${row.action_label}`}
              onClick={() => {
                onOpen({ action: row.action, me: true });
              }}
            >
              Assign me
            </Button>
          ) : null}
        </span>
      ) : null}
    </li>
  );
}
