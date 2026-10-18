// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import type { ExecutionDetail } from "../api/types.gen";
import { duration, executionEvidence, humanizeDurations, reasonSentence, timelineSentence } from "./decision-presentation";
import { decisionPresentation, lapsedApproval } from "./decision-summary";

type Record = Pick<ExecutionDetail, "state" | "reasons" | "observed_effect" | "timeline" | "checkpoint">;
function record(state: string, code?: string): Record {
  return { state, reasons: code === undefined ? [] : [{ code, rule_id: null, sentence: "" }], observed_effect: null, timeline: [], checkpoint: [] };
}

describe("recorded decision explanations", () => {
  it("distinguishes an expired approval from the recorded execution effect", () => {
    const result = decisionPresentation(record("STALE_AUTHORIZATION", "APPROVAL_EXPIRED"));
    expect(result.cause).toContain("approval deadline passed");
    expect(result.execution).toContain("does not establish whether the provider acted");
    expect(result.next).toContain("If no effect occurred");
    expect(result.next).toContain("fresh plan and approval");
    const recordedExpiry = decisionPresentation({ ...record("STALE_AUTHORIZATION", "STALE_AUTHORIZATION"), approval: { state: "EXPIRED" } });
    expect(recordedExpiry.cause).toContain("approval deadline passed");
  });

  it("reads a lapse the server classified, and never an approved one, as lapsed (#678)", () => {
    expect(lapsedApproval({ state: "PENDING_APPROVAL", approval: { state: "PENDING", lapsed: true } })?.code).toBe(
      "APPROVAL_EXPIRED",
    );
    expect(lapsedApproval({ state: "PENDING_APPROVAL", approval: { state: "PENDING", lapsed: false } })).toBeUndefined();
    expect(
      lapsedApproval({ state: "STALE_AUTHORIZATION", approval: { state: "EXPIRED", lapsed: false, unused: true } }),
    ).toBeUndefined();
    const lapsed = decisionPresentation({
      ...record("PENDING_APPROVAL", "APPROVAL_REQUIRED"),
      approval: { state: "PENDING", lapsed: true },
    });
    expect(lapsed.decision).toBe("Approval lapsed");
    expect(lapsed.cause).toBe("The approval deadline passed before it could be used.");
    expect(lapsed.next).toContain("fresh plan and approval");
    expect(lapsed.execution).toBe(
      "Nothing ran. The deadline passed before a decision; the record closes at the next cleanup run.",
    );
    for (const state of ["PENDING_APPROVAL", "STALE_AUTHORIZATION"]) {
      const unused = decisionPresentation({
        ...record(state, state === "PENDING_APPROVAL" ? "APPROVAL_REQUIRED" : "APPROVAL_EXPIRED"),
        approval: { state: state === "PENDING_APPROVAL" ? "APPROVED" : "EXPIRED", lapsed: false, unused: true },
      });
      expect(unused.decision).toBe("Approved, but not used before the deadline");
      expect(JSON.stringify(unused)).not.toContain("Approval lapsed");
      expect(JSON.stringify(unused)).not.toContain("before a decision");
    }
    const waiting = decisionPresentation({ ...record("PENDING_APPROVAL"), approval: { state: "PENDING", lapsed: false } });
    expect(waiting.decision).toBe("Held for a person");
  });

  it("calls a held request held for a person, the word every page uses (#678)", () => {
    expect(decisionPresentation(record("PENDING_APPROVAL")).decision).toBe("Held for a person");
  });

  it("does not turn generic stale or an unknown reason into proof of no execution", () => {
    for (const code of ["STALE_AUTHORIZATION", "NEW_FUTURE_REASON"]) {
      const result = decisionPresentation(record("STALE_AUTHORIZATION", code));
      expect(result.execution).toContain("does not establish whether the provider acted");
      expect(result.cause).not.toContain("NEW_FUTURE_REASON");
      expect(result.execution).not.toContain("nothing");
      expect(result.next.toLowerCase()).not.toContain("retry");
    }
  });

  it("keeps a stale request with an earlier dispatch on the reconciliation path", () => {
    const detail = record("STALE_AUTHORIZATION", "APPROVAL_EXPIRED");
    detail.timeline = [{ at: "2026-09-22T10:00:00Z", kind: "transition", state: "DISPATCH_COMMITTED", actor: null, sentence: "Committed" }];
    expect(decisionPresentation(detail).next).toContain("Do not retry");
    expect(decisionPresentation(detail).next).toContain("Reconcile");
  });

  it.each(["INDETERMINATE", "FAILED_EFFECT_UNKNOWN", "DISPATCH_COMMITTED"])("does not invite retries of %s", (state) => {
    const result = decisionPresentation(record(state, "NEW_FUTURE_REASON"));
    expect(result.decision).toBe("Authorized to proceed");
    expect(result.next).toContain("Do not retry");
    expect(result.next).toContain("Reconcile");
    expect(result.execution).toMatch(/unknown|not confirmed/);
  });

  it("only distinguishes explicit deny and absent permit when the record distinguishes them", () => {
    expect(decisionPresentation(record("DENIED", "EXPLICIT_DENY")).cause).toContain("explicit deny");
    expect(decisionPresentation(record("DENIED", "NO_MATCHING_PERMIT")).cause).toContain("No policy permits");
    expect(decisionPresentation(record("DENIED", "NOT_AUTHORIZED")).cause).toContain("does not distinguish");
    expect(decisionPresentation(record("DENIED", "HUMAN_DENIED")).cause).toContain("reviewer refused");
  });

  it("preserves a specific recorded reason even when its code has a generic fallback", () => {
    const reason = { code: "NOT_AUTHORIZED", rule_id: "deny-tier0", sentence: "Deny endpoint.isolate when privilege_class is tier0." };
    expect(reasonSentence(reason)).toBe(reason.sentence);
    expect(decisionPresentation({ ...record("DENIED"), reasons: [reason] }).cause).toBe(reason.sentence);
    expect(reasonSentence({ ...reason, rule_id: null, sentence: "No rule in the active bundle permits this action for this plan, or a deny rule matched it." })).toContain("does not distinguish");
    expect(reasonSentence({ code: "CONTEXT_EXPIRED", rule_id: null, sentence: "Inventory freshness limit of 3600 seconds was exceeded." })).toBe("Inventory freshness limit of 1 hour was exceeded.");
    expect(reasonSentence({ code: "UNKNOWN_REASON", rule_id: null, sentence: "The protected journal was unavailable." })).toBe("The protected journal was unavailable.");
  });

  it("separates observe-only simulation from enforcement and external execution evidence", () => {
    const detail = { ...record("OBSERVED", "NOT_AUTHORIZED"), observed_effect: "DENY" };
    expect(decisionPresentation(detail).decision).toBe("Observe only");
    expect(decisionPresentation(detail).cause).toContain("would have been denied");
    expect(decisionPresentation(detail).execution).toContain("did not dispatch");
    expect(executionEvidence({ state: "EXECUTED", timeline: [], external: true })).toContain("reported completion");
    expect(executionEvidence({ state: "EXECUTED", timeline: [] })).not.toContain("provider");
    expect(executionEvidence({ state: "NEW_STATE", timeline: [] })).toContain("not established");
  });

  it.each(["PROVIDER_RESPONSE", "EXECUTOR_REPORT", "REPORTED_FAILURE", "UNREPORTED_GRANT", "INCONCLUSIVE_JOURNAL", "INVALID_ARGUMENTS", "DEPENDENCY_UNAVAILABLE"])(
    "gives %s a sentence even when the API sends none",
    (code) => {
      const sentence = reasonSentence({ code, rule_id: null, sentence: "" });
      expect(sentence).not.toContain("without a plain-language explanation");
      expect(sentence).not.toContain(code);
    },
  );

  it("says who confirmed an executed record's outcome and keeps its next step", () => {
    const result = decisionPresentation(record("EXECUTED", "PROVIDER_RESPONSE"));
    expect(result.cause).toBe("The provider's own response confirmed this outcome.");
    expect(result.next).toContain("Review the recorded result");
    expect(timelineSentence({ sentence: "Failed before any effect: PROVIDER_RESPONSE." })).toBe(
      "Failed before any effect: The provider's own response confirmed this outcome.",
    );
    expect(timelineSentence({ sentence: "Authorization went stale: APPROVAL_EXPIRED, CONTEXT_EXPIRED." })).toBe(
      "Authorization went stale: The approval deadline passed before it could be used, The trusted facts used for this request expired.",
    );
  });

  it("keeps an unreported grant on the reconciliation path", () => {
    const result = decisionPresentation(record("INDETERMINATE", "UNREPORTED_GRANT"));
    expect(result.cause).toContain("report window closed");
    expect(result.next).toContain("Do not retry");
  });

  it("shows a denial's matching rule and a reconciliation note as the API words them", () => {
    const rule = { code: "NOT_AUTHORIZED", rule_id: null, sentence: "This request matches the deny rule isolate-never-domain-controller: Deny endpoint.isolate when role is domain_controller." };
    expect(decisionPresentation({ ...record("DENIED"), reasons: [rule] }).cause).toBe(rule.sentence);
    const note = { code: "Scheduled recovery 1", rule_id: null, sentence: "Settled by reconciliation, noting: Scheduled recovery 1" };
    expect(reasonSentence(note)).toBe(note.sentence);
  });

  it("keeps raw timeline reason codes out of the plain-language timeline", () => {
    expect(timelineSentence({ sentence: "Denied: NOT_AUTHORIZED." })).toContain("Policy did not authorize");
    expect(timelineSentence({ sentence: "Authorization went stale: FUTURE_REASON." })).not.toContain("FUTURE_REASON");
    expect(timelineSentence({ kind: "decision", sentence: "Approved by SOC_TEAM." })).toBe("Approved by SOC_TEAM.");
  });

  it("makes durations readable without changing their value", () => {
    expect(duration(3600)).toBe("1 hour");
    expect(duration(7200)).toBe("2 hours");
    expect(duration(3660)).toBe("1 hour 1 minute");
    expect(duration(90)).toBe("1 minute 30 seconds");
    expect(humanizeDurations("At most 10 targets per 3600 seconds.")).toBe("At most 10 targets per 1 hour.");
  });
});
