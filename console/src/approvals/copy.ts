// SPDX-License-Identifier: AGPL-3.0-only
// The words of the Approvals page (#333): the copy each refusal code maps to, and the
// sentence each status shows instead of the decision bar. Every value here is fixed text; a
// string that came from an agent, a provider or a label is rendered beside it, never inside it.

import type { ApprovalDetail, ApprovalItem } from "../api/types.gen";
import type { Tone } from "../components/ui/Badge";
import { executionEvidence, uncertainExecution } from "../lib/decision-presentation";
import { APPROVAL_WORDS, VERDICT_WORDS } from "../lib/words";

export const REFUSALS: Record<string, string> = {
  STOPPED: "The emergency stop is active. Decisions resume when an administrator releases it.",
  APPROVAL_EXPIRED: "This approval lapsed. Reload the request and review its execution history before requesting a fresh plan.",
  ALREADY_DECIDED: "Your decision on this approval is already recorded.",
  CONFLICT: "This approval changed first; it has been reloaded.",
  NOT_FOUND: "This approval is no longer in your scope.",
  INVALID_CONTINUATION: "The page and the approval no longer match; it has been reloaded.",
  INVALID_BODY: "The comment was refused. It may hold something that looks like a secret.",
  FORBIDDEN: "This session cannot decide approvals.",
  SESSION_REQUIRED: "Your session has ended. Sign in again.",
  UNAVAILABLE: "ExecBound is unavailable. Reload the request to check whether your decision was recorded.",
};

export const FALLBACK = "The result could not be confirmed. Reload the request to check whether your decision was recorded.";

/** The typed code of a console API refusal, when the thrown value carries one. */
export function refusalCode(error: unknown): string | null {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code: unknown = error.code;
    if (typeof code === "string") return code;
  }
  return null;
}

/** The end of every lapse sentence an approver reads: what they can and cannot do about it. */
const SEND_AGAIN = "If the agent still needs this, it must send the request again.";

/**
 * A decision refused because the approval lapsed, for someone who is not an administrator
 * (#678): they may have come from a message and have no way to read the agent's history.
 */
export const LAPSED_BEFORE_DECISION = `This approval lapsed before your decision reached it. Nothing ran. ${SEND_AGAIN}`;

/** The copy a refusal shows; `admin` keeps the execution-history advice an approver cannot act on. */
export function refusalText(error: unknown, admin = false): string {
  const code = refusalCode(error);
  if (code === "APPROVAL_EXPIRED" && !admin) return LAPSED_BEFORE_DECISION;
  return (code !== null ? REFUSALS[code] : undefined) ?? FALLBACK;
}

/**
 * What a lapsed approval says to someone who is not an administrator (#678): which of its
 * three histories it had, read from the quorum the detail carries, whether anything ran, and
 * that only the agent can ask again. Never "before anyone decided it" to someone who approved.
 */
export function lapseNotice(detail: ApprovalDetail): string {
  const { recorded, required } = detail.quorum;
  const first =
    recorded === 0
      ? "This approval lapsed before anyone decided it."
      : recorded < required
        ? "This approval lapsed before enough people approved it."
        : "This approval was approved but lapsed before the agent used it.";
  const state = detail.item.execution_state;
  const nothingRan =
    (state === "PENDING_APPROVAL" || state === "STALE_AUTHORIZATION") &&
    !uncertainExecution({ state, timeline: detail.timeline });
  return [first, nothingRan ? "Nothing ran." : null, SEND_AGAIN].filter((part) => part !== null).join(" ");
}

/**
 * Whether an approval has lapsed, as the queue reads its rows (#678): the server says so
 * (`expired`), or it was still pending when last read and its deadline has passed since, between
 * one poll and the next. Nothing on a lapsed approval may say that it is still waiting.
 */
export function lapsed(detail: ApprovalDetail, secondsLeft: number): boolean {
  return detail.status === "expired" || (detail.status === "pending" && secondsLeft <= 0);
}

/**
 * The detail's execution line (#678). A request whose approval lapsed is no longer waiting for
 * one; any other request reads its recorded state as the record does.
 */
export function executionLine(detail: ApprovalDetail, lapse: boolean): string {
  const record = { state: detail.item.execution_state, timeline: detail.timeline };
  return lapse && record.state === "PENDING_APPROVAL" && !uncertainExecution(record)
    ? "The approval lapsed, so this request cannot run. No provider execution is recorded."
    : executionEvidence(record);
}

/**
 * What the page says when there is nothing to decide, by the detail's status. `admin` is
 * whether the reader is an administrator, who keeps the execution-history advice on a lapse.
 */
export function statusNotice(detail: ApprovalDetail, admin = false): { text: string; tone: Tone } | null {
  switch (detail.status) {
    case "pending":
      return null;
    case "decided":
      return {
        tone: "allow",
        text:
          `Your decision (${word(detail.quorum.mine)}) is recorded. ` +
          `${String(detail.quorum.recorded)} of ${String(detail.quorum.required)} approvals recorded; ` +
          "the approval waits for the remaining approvers.",
      };
    case "expired":
      return admin
        ? { tone: "stale", text: "This approval lapsed and cannot be used. Review the execution history before asking the agent for a fresh plan." }
        : { tone: "stale", text: lapseNotice(detail) };
    case "paused":
      return {
        tone: "deny",
        text: "Decisions are paused while the emergency stop is active. They resume when an administrator releases it.",
      };
    case "settled":
      if (uncertainExecution({ state: detail.item.execution_state, timeline: detail.timeline })) {
        return { tone: "stale", text: "The request's effect is not confirmed. Do not retry the action; reconcile the recorded evidence first." };
      }
      return {
        tone: stateTone(detail.item.approval_state),
        text:
          `Approval: ${APPROVAL_WORDS[detail.item.approval_state] ?? detail.item.approval_state}. ` +
          `Request: ${detail.item.execution_state_label}. Nothing more can be decided here. ` +
          executionEvidence({ state: detail.item.execution_state, timeline: detail.timeline }),
      };
  }
}

/** A person's answer as the flow says it: "approve" or "refuse" (#678). */
export function word(decision: "APPROVE" | "DENY" | null | undefined): string {
  return decision === "APPROVE" || decision === "DENY" ? VERDICT_WORDS[decision] : "none";
}

/** The badge an approval carries, word first. */
export function stateBadge(item: ApprovalItem, forYou = false): { text: string; tone: Tone } {
  switch (item.approval_state) {
    case "PENDING":
      return { text: forYou ? "Waiting for you" : "Waiting for a person", tone: "hold" };
    case "APPROVED":
    case "CONSUMED":
      return { text: APPROVAL_WORDS.APPROVED ?? "Approved", tone: "allow" };
    case "DENIED":
      // A person's refusal; a policy's denial of a request is the request's own "Denied".
      return { text: APPROVAL_WORDS.DENIED ?? "Refused", tone: "deny" };
    default:
      return { text: APPROVAL_WORDS[item.approval_state] ?? item.approval_state, tone: "stale" };
  }
}

export function stateTone(state: string): Tone {
  if (state === "APPROVED" || state === "CONSUMED") return "allow";
  if (state === "DENIED") return "deny";
  if (state === "PENDING") return "hold";
  return "stale";
}
