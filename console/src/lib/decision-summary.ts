// SPDX-License-Identifier: AGPL-3.0-only
// What a record's drawer and its row say about the decision: the summary the drawer leads with
// and the lapse a row names. Kept apart from `decision-presentation.ts`, whose sentences the
// approval page imports, so the cold approval link carries none of this (#678).

import type { ExecutionDetail, ReasonView } from "../api/types.gen";
import type { Tone } from "../components/ui/Badge";
import { executionEvidence, REASONS, reasonSentence, uncertainExecution } from "./decision-presentation";
import { toneFor } from "./words";

/** An approval as the server classifies it on its own clock (#678): lapsed or unused. */
export type ApprovalLapse = { state: string; lapsed?: boolean; unused?: boolean } | null;

/**
 * The approval-deadline reason, when a stale or held request's approval lapsed before anybody
 * decided it. The server says so (`lapsed`), on its own clock, before and after the recovery
 * run's sweep; an approval a person approved and the agent did not use is not a lapse before
 * a decision. The record's pages and its rows both ask this, so a row never reads more vaguely
 * than the record it opens.
 */
export function lapsedApproval(record: { state: string; approval?: ApprovalLapse }): ReasonView | undefined {
  const approval = record.approval;
  return approval && (approval.lapsed ?? (approval.state === "EXPIRED" && !approval.unused)) &&
    ["STALE_AUTHORIZATION", "PENDING_APPROVAL"].includes(record.state)
    ? { code: "APPROVAL_EXPIRED", sentence: "", rule_id: null }
    : undefined;
}

/**
 * The badge a record carries, in its Activity row and atop its drawer alike (#678): a lapse or an
 * unused approval as the server classified it on its own clock, before and after the sweep, and
 * otherwise the state's own word. A held request whose approval lapsed is not "Held".
 */
export function recordBadge(record: { state: string; state_label: string; approval?: ApprovalLapse }): { text: string; tone: Tone } {
  if (record.approval?.lapsed === true) return { text: "Lapsed", tone: "stale" };
  if (record.approval?.unused === true) return { text: "Not used", tone: "stale" };
  return { text: record.state_label, tone: toneFor(record.state) };
}

export function decisionPresentation(detail: Pick<ExecutionDetail, "state" | "reasons" | "observed_effect" | "timeline" | "checkpoint"> & {
  approval?: ApprovalLapse;
}) {
  const record = { state: detail.state, timeline: detail.timeline, external: detail.checkpoint.length > 0 };
  const specific = detail.reasons.find((item) => item.code !== "STALE_AUTHORIZATION" && REASONS[item.code] !== undefined);
  const lapse = lapsedApproval(detail);
  const unused = detail.approval?.unused === true;
  // A held request whose approval ran out: what happened is the deadline, not the hold.
  const ranOut = detail.state === "PENDING_APPROVAL" && (lapse !== undefined || unused);
  const reason = (ranOut ? { code: "APPROVAL_EXPIRED", sentence: "", rule_id: null } : undefined) ?? specific ?? lapse ?? detail.reasons.find((item) => REASONS[item.code] !== undefined);
  const unknownCause = "No specific cause is recorded. Inspect the technical details and timeline with an administrator.";
  let decision: string;
  switch (detail.state) {
    case "DENIED": decision = "Request denied"; break;
    case "PENDING_APPROVAL": decision = lapse !== undefined ? "Approval lapsed" : unused ? UNUSED : "Held for a person"; break;
    case "STALE_AUTHORIZATION": decision = unused ? UNUSED : "Authorization no longer valid"; break;
    case "OBSERVED": decision = "Observe only"; break;
    case "EXECUTED":
    case "DISPATCH_COMMITTED":
    case "INDETERMINATE":
    case "FAILED_EFFECT_UNKNOWN":
    case "FAILED_NOT_EXECUTED": decision = "Authorized to proceed"; break;
    default: decision = "Decision not yet established";
  }
  let cause = reason !== undefined ? reasonSentence(reason) : detail.reasons.map(reasonSentence).join(" ") || unknownCause;
  let next = reason !== undefined ? REASONS[reason.code]?.next ?? unknownCause : "Review the recorded evidence before taking further action.";
  if (detail.state === "OBSERVED") {
    const effect: Record<string, string> = { ELIGIBLE: "eligible to run", REQUIRE_APPROVAL: "held for approval", DENY: "denied" };
    const observed = detail.observed_effect !== null ? effect[detail.observed_effect] : undefined;
    cause = `This request was evaluated in observe mode${observed !== undefined ? ` and would have been ${observed}` : ""}.${detail.reasons.length > 0 ? ` ${cause}` : ""}`;
    next = "Review the simulated decision. Use an enforced path when this action must be controlled.";
  } else if (uncertainExecution(record)) {
    next = "Do not retry this action. Reconcile the retained provider or executor evidence before deciding what to do next.";
  } else if (detail.state === "EXECUTED") {
    cause = detail.reasons.length > 0 ? cause : "The request passed the required checks and an execution outcome was recorded.";
    next = "Review the recorded result. Use a separate governed action if the effect needs to be reversed.";
  } else if (detail.state === "PENDING_APPROVAL" && reason === undefined) {
    cause = "A person's approval is required before this request can proceed.";
    next = "An assigned reviewer can inspect the request and decide before its deadline.";
  }
  const execution = ranOut
    ? `Nothing ran. ${unused ? "The agent did not use the approval before its deadline" : "The deadline passed before a decision"}; the record closes at the next cleanup run.`
    : executionEvidence(record);
  return { decision, cause, execution, next };
}

const UNUSED = "Approved, but not used before the deadline";
