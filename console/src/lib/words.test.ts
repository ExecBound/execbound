// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { APPROVAL_WORDS, DECIDED_WORDS, TERMS, VERDICT_WORDS } from "./words";

describe("the console's vocabulary (#678)", () => {
  it("words a person's answer and an approval's state one way", () => {
    expect(VERDICT_WORDS).toEqual({ APPROVE: "approve", DENY: "refuse" });
    expect(DECIDED_WORDS).toEqual({ APPROVE: "approved", DENY: "refused" });
    expect(APPROVAL_WORDS).toEqual({
      PENDING: "Waiting for a person",
      APPROVED: "Approved",
      CONSUMED: "Approved",
      DENIED: "Refused",
      EXPIRED: "Lapsed",
      INVALIDATED: "No longer valid",
    });
  });

  it("holds the terms Help's glossary renders, each once", () => {
    const terms = TERMS.map((entry) => entry.term);
    for (const wanted of [
      "Workspace",
      "Space",
      "Approval rule",
      "Impact limit",
      "Enforcing, Observe only",
      "Uncertain outcome (Unsettled, Effect unknown)",
      "Lapsed",
      "Agent 3, User 3",
    ]) {
      expect(terms).toContain(wanted);
    }
    expect(new Set(terms).size).toBe(terms.length);
    // Help adds no "Uncertain" entry of its own: the uncertain outcome is this one term.
    expect(terms.filter((term) => term.startsWith("Uncertain"))).toHaveLength(1);
    for (const entry of TERMS) expect(entry.meaning.length).toBeGreaterThan(0);
  });
});
