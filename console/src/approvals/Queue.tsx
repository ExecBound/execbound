// SPDX-License-Identifier: AGPL-3.0-only
import { Link } from "@tanstack/react-router";
import { lazy, Suspense } from "react";

import type { ApprovalItem } from "../api/types.gen";
import { CountdownRing, clock } from "../components/charts/CountdownRing";
import { Badge } from "../components/ui/Badge";
import { EmptyState } from "../components/ui/EmptyState";
import { Time } from "../components/ui/Time";
import { holdFocus } from "../lib/focus";
import { useTimeZone, zoneName } from "../lib/time";
import { refName } from "../components/directory/handles";
import { stateBadge } from "./copy";
import { focusDetailNext } from "./focus";
import type { ApprovalsView } from "./search";
import { secondsUntil } from "./time";

export type View = ApprovalsView;

const Coverage = lazy(() => import("./Others").then((module) => ({ default: module.Coverage })));
const LateFlag = lazy(() => import("./Others").then((module) => ({ default: module.LateFlag })));

/**
 * The queue: one link per approval, the ring counting down beside a pending one and the
 * decision beside a decided one. `j` and `k` move between rows from anywhere on the page, as on
 * Activity (`data-rows`, which the shell's keyboard reads); opening a row keeps the focus
 * in the work rather than sending it to the page heading, and the detail takes it.
 *
 * An approval whose deadline has passed is never a countdown reading `0:00`, whichever view
 * it is in: it reads Lapsed, with the moment it lapsed, because nobody can act on it
 * (#426).
 *
 * Each row's link carries the view, so opening a row and pressing Back returns to the same
 * chip (#678). A row waiting on others counts down as Pending does and says how far its quorum
 * has got and who can decide it.
 */
export function Queue({
  items,
  view,
  now,
  title,
  emptyTitle,
  emptyBody = "When an agent asks for something a person must decide, it appears here.",
  flagLate = false,
}: {
  items: ApprovalItem[];
  view: View;
  now: number;
  title?: string;
  emptyTitle: string;
  emptyBody?: string;
  /** An administrator's Lapsed view: flag each row whose message came too late (#678). */
  flagLate?: boolean;
}) {
  const [choice] = useTimeZone();
  if (items.length === 0) {
    return <EmptyState title={emptyTitle}>{emptyBody}</EmptyState>;
  }
  return (
    <>
    <p className="queue-caption muted">Times in {zoneName(choice)}</p>
    <ul className="queue-list" aria-label={title ?? "Approvals"} data-rows="a.queue-row">
      {items.map((item) => {
        const left = secondsUntil(item.expires_at, now);
        const tone = left <= item.total_seconds / 4 ? "deny" : "hold";
        // The server decides what has lapsed; the clock check is for a row that runs out
        // while somebody is looking at the queue, between one poll and the next.
        const lapsed = view === "lapsed" || (item.approval_state === "PENDING" && left <= 0);
        const counting = (view === "pending" || view === "others") && item.approval_state === "PENDING" && !lapsed;
        const badge = lapsed ? { text: "Lapsed", tone: "stale" as const } : stateBadge(item);
        return (
          <li key={item.approval_id}>
            <Link
              to="/approvals/$approvalId"
              params={{ approvalId: item.approval_id }}
              search={view === "pending" ? {} : { view }}
              className="queue-row"
              activeProps={{ className: "queue-row queue-row-active", "aria-current": "page" }}
              onClick={() => {
                holdFocus();
                focusDetailNext();
              }}
            >
              <span className="queue-mark">
                {counting ? (
                  <CountdownRing
                    remainingSeconds={left}
                    totalSeconds={item.total_seconds}
                    label={`${clock(left)} left`}
                  />
                ) : (
                  <span className={`queue-dot queue-dot-${badge.tone}`} aria-hidden="true" />
                )}
              </span>
              <span className="queue-main">
                <strong>{item.action_label}</strong>
                <span className="queue-target">
                  <span className="mono">{item.target}</span>
                  {" · "}
                  {String(item.resource_class)}
                </span>
                <small>
                  {item.request_ref} · {refName(item.agent)} · <Time at={item.created_at} form="clock" />
                  {lapsed ? (
                    <>
                      {" · lapsed "}
                      <Time at={item.expires_at} precision="second" />
                    </>
                  ) : null}
                </small>
                {view === "others" ? (
                  <Suspense fallback={null}>
                    <Coverage item={item} />
                  </Suspense>
                ) : null}
                {flagLate ? (
                  <Suspense fallback={null}>
                    <LateFlag item={item} />
                  </Suspense>
                ) : null}
              </span>
              {counting ? (
                <span className={`queue-left mono tone-${tone}`}>
                  {clock(left)}
                  <span className="sr-only"> left</span>
                  {item.mine !== null ? <span className="sr-only">, your decision is recorded</span> : null}
                </span>
              ) : (
                <Badge tone={badge.tone}>{badge.text}</Badge>
              )}
            </Link>
          </li>
        );
      })}
    </ul>
    </>
  );
}
