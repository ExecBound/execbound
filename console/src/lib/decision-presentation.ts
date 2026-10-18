// SPDX-License-Identifier: AGPL-3.0-only
import type { ReasonView, TimelineEntry } from "../api/types.gen";

/** Fixed explanations of recorded evidence. These never re-evaluate policy or predict effects. */
export const REASONS: Record<string, { cause: string; next: string }> = {
  APPROVAL_EXPIRED: {
    cause: "The approval deadline passed before it could be used.",
    next: "Review the execution history. If no effect occurred and the action is still needed, request a fresh plan and approval.",
  },
  CONTEXT_EXPIRED: {
    cause: "The trusted facts used for this request expired.",
    next: "Refresh the trusted context and review the execution history before requesting a new plan.",
  },
  INVALID_CONTEXT: {
    cause: "The trusted context was invalid or no longer fresh enough for this decision.",
    next: "Check the context source and freshness, then evaluate a fresh plan.",
  },
  EXPLICIT_DENY: {
    cause: "An explicit deny policy matched this request.",
    next: "Review the matching policy with its owner. Approval cannot override a deny.",
  },
  NO_MATCHING_PERMIT: {
    cause: "No policy permits this action for this account and target.",
    next: "Ask the policy owner to review the intended access. Only add a permit if the action should be allowed.",
  },
  NOT_AUTHORIZED: {
    cause: "Policy did not authorize this request. This record does not distinguish a matching deny from a missing permit.",
    next: "Review the policy and frozen facts with the policy owner. Approval cannot override a deny.",
  },
  APPROVAL_REQUIRED: {
    cause: "Policy or an impact limit requires a person's approval.",
    next: "An assigned reviewer can inspect the request and decide before its deadline.",
  },
  HUMAN_DENIED: {
    cause: "A reviewer refused this request.",
    next: "Read the reviewer's decision and resolve the concern before requesting a different plan.",
  },
  VERSION_MISMATCH: {
    cause: "The target changed after this plan was prepared.",
    next: "Inspect the recorded outcome and current target state before evaluating a new plan.",
  },
  STALE_AUTHORIZATION: {
    cause: "The authorization no longer matches the current request conditions. The record does not identify a more specific cause.",
    next: "Inspect the timeline, approval and trusted context. Confirm the earlier outcome before requesting a fresh plan.",
  },
  INVALID_APPROVAL: {
    cause: "The approval did not match the exact plan being executed.",
    next: "Check the approval and plan details. A changed plan needs its own review.",
  },
  CHANGED_OBLIGATIONS: {
    cause: "Review requirements changed after the approval was recorded.",
    next: "Review the current policy requirements and request a fresh plan if the action is still needed.",
  },
  // How a settled outcome was settled. One code labels an executed record, one that failed
  // before any effect and one refused on the target's version, so the cause says who answered.
  PROVIDER_RESPONSE: {
    cause: "The provider's own response confirmed this outcome.",
    next: "Review the provider's recorded result before requesting the action again.",
  },
  EXECUTOR_REPORT: {
    cause: "The executor reported the outcome itself.",
    next: "Review the executor's report and the evidence tier it was settled at.",
  },
  REPORTED_FAILURE: {
    cause: "The executor reported that its call failed.",
    next: "Read the executor's failure report before requesting the action again.",
  },
  UNREPORTED_GRANT: {
    cause: "The executor's report window closed without a report.",
    next: "Do not retry. Reconcile the executor's own record of what it did before deciding what to do next.",
  },
  INCONCLUSIVE_JOURNAL: {
    cause: "The provider's journal held no terminal evidence.",
    next: "Do not retry. Reconcile with the provider's journal before deciding what to do next.",
  },
  INVALID_ARGUMENTS: {
    cause: "The frozen arguments no longer match the action's catalog entry.",
    next: "Request a fresh plan with arguments the action accepts.",
  },
  DEPENDENCY_UNAVAILABLE: {
    cause: "The decision could not be made because of an unexpected error.",
    next: "Ask an administrator to check the service's logs, then request the action again. This request was not dispatched.",
  },
};

// Older APIs supplied these stock descriptions. They carry no request-specific evidence;
// the expiry sentence was also too narrow because an approved plan can expire before use.
const LEGACY_SENTENCES: Record<string, string> = {
  NOT_AUTHORIZED: "No rule in the active bundle permits this action for this plan, or a deny rule matched it.",
  APPROVAL_EXPIRED: "The approval ran out of time before anybody decided it.",
};

export function reasonSentence(reason: ReasonView): string {
  const recorded = reason.sentence.trim();
  if (recorded !== "" && recorded !== LEGACY_SENTENCES[reason.code]) return humanizeDurations(recorded);
  return REASONS[reason.code]?.cause ?? "A reason was recorded without a plain-language explanation.";
}

export function humanizeDurations(sentence: string): string {
  return sentence.replace(/\b(\d+) seconds\b/g, (_match, seconds: string) => duration(Number(seconds)));
}

export function timelineSentence(entry: Pick<TimelineEntry, "sentence"> & Partial<Pick<TimelineEntry, "kind">>): string {
  if (entry.kind !== undefined && entry.kind !== "transition") return entry.sentence;
  // A cause is a whole sentence with its own full stop, so the stop after the code it
  // replaces is kept only once.
  return humanizeDurations(entry.sentence).replace(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b(\.?)/g,
    (_match, code: string, stop: string) =>
      (code === "NOT_AUTHORIZED" ? "Policy did not authorize this request" : REASONS[code]?.cause ?? "additional recorded detail").replace(/\.$/, "") + stop);
}

export function duration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "an unknown duration";
  if (seconds === 0) return "0 seconds";
  const parts: string[] = [];
  let remaining = seconds;
  for (const [size, unit] of [[86_400, "day"], [3_600, "hour"], [60, "minute"], [1, "second"]] as const) {
    if (remaining >= size) {
      const count = Math.floor(remaining / size);
      remaining %= size;
      parts.push(`${String(count)} ${unit}${count === 1 ? "" : "s"}`);
    }
  }
  return parts.join(" ") || `${String(seconds)} seconds`;
}

export interface ExecutionEvidence {
  state: string;
  timeline: Pick<TimelineEntry, "state">[];
  external?: boolean;
}

const UNCERTAIN = new Set(["INDETERMINATE", "FAILED_EFFECT_UNKNOWN", "DISPATCH_COMMITTED"]);
const MAY_HAVE_ACTED = new Set([...UNCERTAIN, "EXECUTED"]);

export function uncertainExecution(record: ExecutionEvidence): boolean {
  return UNCERTAIN.has(record.state) || (
    record.state === "STALE_AUTHORIZATION" && record.timeline.some((entry) => entry.state !== null && MAY_HAVE_ACTED.has(entry.state))
  );
}

/** A decision and a completion are separate. In particular, stale is never proof of no effect. */
export function executionEvidence(record: ExecutionEvidence): string {
  switch (record.state) {
    case "EXECUTED":
      return record.external === true
        ? "An external executor reported completion. See the retained evidence and its limits below."
        : record.external === false
          ? "The recorded provider result confirms execution."
          : "The record shows execution completed. Review the retained evidence and its limits below.";
    case "FAILED_NOT_EXECUTED":
      return record.external === true
        ? "The recorded external result reports no effect. See its evidence and limits below."
        : "The recorded outcome reports no execution effect. Review the retained evidence and its limits below.";
    case "OBSERVED":
      return "ExecBound observed this request and did not dispatch it. Actions taken outside this path are not established by this record.";
    case "DENIED":
      return "ExecBound refused this request before dispatch. It does not establish what happened outside this controlled path.";
    case "PENDING_APPROVAL":
      return "This request is waiting for approval; no provider execution is recorded yet.";
    case "INDETERMINATE":
    case "FAILED_EFFECT_UNKNOWN":
      return "The effect is unknown. The action may have happened even though completion was not confirmed.";
    case "DISPATCH_COMMITTED":
      return "Execution was committed, but completion is not confirmed yet.";
    case "STALE_AUTHORIZATION":
      return "Authorization is no longer valid. This status alone does not establish whether the provider acted.";
    case "ATTEMPTED":
    case "RESERVED":
      return "The request is being prepared. No completed execution is recorded yet.";
    default:
      return "The execution outcome is not established by this record's status.";
  }
}
