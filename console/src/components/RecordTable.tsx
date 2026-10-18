// SPDX-License-Identifier: AGPL-3.0-only
import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { readExecutionOptions } from "../api/@tanstack/react-query.gen";
import type { ExecutionSummary } from "../api/types.gen";
import { reasonSentence } from "../lib/decision-presentation";
import { lapsedApproval, recordBadge } from "../lib/decision-summary";
import { dayHeading, dayKey } from "../lib/days";
import { useTimeZone, zoneName } from "../lib/time";
import { PrincipalName } from "./PrincipalName";
import { Badge } from "./ui/Badge";
import { Table, Td, Th, type Density } from "./ui/Table";
import { Time } from "./ui/Time";
import "./record-table.css";

/**
 * The one line a row says beside its badge: the first reason, or what the state means. A
 * lapsed approval stands in for the generic stale reason, as it does on the record itself.
 */
export function note(item: ExecutionSummary): string {
  const first = item.reasons[0];
  // An approval that ran out reads as what happened, before the hold or stale reason, as the
  // record it opens reads it (#678).
  const lapse = lapsedApproval(item);
  if (item.state === "PENDING_APPROVAL" && lapse !== undefined) return reasonSentence(lapse);
  if (item.approval?.unused === true) return "Approved, but not used before the deadline.";
  const reason = first === undefined || first.code === "STALE_AUTHORIZATION" ? (lapsedApproval(item) ?? first) : first;
  if (reason !== undefined) {
    return reasonSentence(reason);
  }
  switch (item.state) {
    case "DISPATCH_COMMITTED":
    case "INDETERMINATE":
      return "Awaiting provider evidence";
    case "EXECUTED":
      return "Allowed and executed";
    case "OBSERVED":
      return "Observed only";
    case "STALE_AUTHORIZATION":
      return "Authorization is no longer valid. Open the request for its reason and outcome.";
    case "DENIED":
      return "Request denied. Open the request for its reason.";
    default:
      return "";
  }
}

/** How long a prefetched record is fresh enough for the drawer not to read it again. */
export const PREFETCH_MS = 5_000;

function Row({
  item,
  open,
  onOpen,
  extra,
  day,
  dated,
}: {
  item: ExecutionSummary;
  open: boolean;
  onOpen: (id: string) => void;
  extra?: (item: ExecutionSummary) => ReactNode;
  /** The day this row starts, where it is the first row of one; times alone read as a fault. */
  day?: string;
  /** Without day headings, a row from any day but today prints its date before its time (#678). */
  dated: boolean;
}) {
  const line = note(item);
  const badge = recordBadge(item);
  const queryClient = useQueryClient();
  // A mouse resting on a row, or the keyboard on its button, reads the record the drawer will
  // show, so it opens without waiting; a touch is a tap and opens it at once. A read only.
  const prefetch = () => {
    queryClient
      .query({ ...readExecutionOptions({ path: { execution_id: item.execution_id } }), staleTime: PREFETCH_MS })
      .catch(() => undefined);
  };
  return (
    <tr
      data-open={open}
      onClick={() => {
        onOpen(item.execution_id);
      }}
      onPointerEnter={(event) => {
        if (event.pointerType === "mouse") prefetch();
      }}
    >
      <Td>
        {day !== undefined ? <span className="row-day">{day}</span> : null}
        <Time at={item.created_at} form={dated ? "listed" : "clock"} />
      </Td>
      <Td>
        <PrincipalName principal={item.agent} link />
      </Td>
      <Td>
        <button
          type="button"
          className="row-link"
          data-record-id={item.execution_id}
          aria-expanded={open}
          onFocus={prefetch}
          onClick={(event) => {
            event.stopPropagation();
            onOpen(item.execution_id);
          }}
        >
          {item.action_label}
        </button>
        <small className="mono request-ref">{item.request_ref}</small>
      </Td>
      <Td>
        <span className="mono">{item.target.provider_id}</span> <span className="muted">{item.target.resource_class}</span>
        {item.target.sample === true ? <> <Badge tone="accent">Sample</Badge></> : null}
      </Td>
      <Td>
        {/* A lapse the server classified reads as one, in the stale tone, before the sweep. */}
        <Badge tone={badge.tone}>{badge.text}</Badge>
      </Td>
      <Td className="reason" title={line}>
        {line}
      </Td>
      {extra !== undefined ? <Td className="row-actions">{extra(item)}</Td> : null}
    </tr>
  );
}

/**
 * Records as rows (#333): time, agent, action, target, the decision as a word-first
 * badge and one line of why. The action is a button that opens the record, so the keyboard
 * reaches every row; the whole row answers a pointer. Every string is the server's, as text.
 * With `days`, the first row of each day carries that day above its time, so a list that
 * crosses midnight is never read as a sorting fault
 * (#427). Without it, a row from any day
 * but the viewer's today prints its date before its time, so an earlier day's row never reads as
 * today's (#678). On a phone each row stacks, so no column is out of sight.
 */
export function RecordTable({
  caption,
  items,
  open,
  onOpen,
  density = "comfortable",
  extra,
  days = false,
}: {
  caption: string;
  items: ExecutionSummary[];
  open: string | undefined;
  onOpen: (id: string) => void;
  density?: Density;
  extra?: (item: ExecutionSummary) => ReactNode;
  days?: boolean;
}) {
  // The day each row starts, where it starts one: a pure pass over the rows, so the table
  // renders the same whenever React draws it.
  const [choice] = useTimeZone();
  const marks = items.map((item, index) => {
    if (!days) return undefined;
    const before = items[index - 1];
    return before === undefined || dayKey(before.created_at, choice) !== dayKey(item.created_at, choice)
      ? dayHeading(item.created_at, choice)
      : undefined;
  });
  return (
    <Table caption={caption} density={density} className="record-table">
      <thead>
        <tr>
          <Th>Time ({zoneName(choice)})</Th>
          <Th>Agent</Th>
          <Th>Action</Th>
          <Th>Target</Th>
          <Th>Decision</Th>
          <Th>Note</Th>
          {extra !== undefined ? (
            <Th>
              <span className="sr-only">Actions</span>
            </Th>
          ) : null}
        </tr>
      </thead>
      <tbody>
        {items.map((item, index) => (
          <Row
            key={item.execution_id}
            item={item}
            open={item.execution_id === open}
            onOpen={onOpen}
            extra={extra}
            day={marks[index]}
            dated={!days}
          />
        ))}
      </tbody>
    </Table>
  );
}
