// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { forgetServerTime } from "./clock";
import {
  clearDrafts,
  DRAFT_LIMIT,
  flushDrafts,
  POLICY_DEBOUNCE_MS,
  POLICY_LIFE_MS,
  POLICY_LIMIT,
  removeApprovalDraft,
  restoreApprovalDraft,
  restorePolicyDraft,
  saveApprovalDraft,
  savePolicyDraft,
} from "./drafts";
import { FLUSH_DRAFTS } from "./kept";

const ID = "4b1e90c2-0000-4000-8000-000000000001";

beforeEach(() => {
  window.sessionStorage.clear();
});

describe("the draft store (#678)", () => {
  it("keeps one approval's text under its own key in this tab's storage alone", () => {
    saveApprovalDraft(ID, "p-1", "2099-01-01T00:00:00Z", "x".repeat(DRAFT_LIMIT + 20));
    const raw = window.sessionStorage.getItem(`eb:draft:approval:${ID}`);
    expect(raw).not.toBeNull();
    expect((JSON.parse(raw ?? "{}") as { t: string }).t).toHaveLength(DRAFT_LIMIT);
    expect(window.localStorage.length).toBe(0);
    expect(restoreApprovalDraft(ID, "p-1", Date.parse("2026-10-09T00:00:00Z"))).toHaveLength(DRAFT_LIMIT);
    removeApprovalDraft(ID);
    expect(window.sessionStorage.getItem(`eb:draft:approval:${ID}`)).toBeNull();
  });

  it("refuses a malformed entry as nothing kept", () => {
    window.sessionStorage.setItem(`eb:draft:approval:${ID}`, "not json");
    expect(restoreApprovalDraft(ID, "p-1", 0)).toBeNull();
    window.sessionStorage.setItem(`eb:draft:approval:${ID}`, JSON.stringify({ p: "p-1", x: 5, t: "x" }));
    expect(restoreApprovalDraft(ID, "p-1", 0)).toBeNull();
  });
});

describe("the new policy document (#678)", () => {
  const KEY = "eb:draft:policy:new";
  const NOW = Date.parse("2026-10-11T12:00:00Z");
  const stored = () => JSON.parse(window.sessionStorage.getItem(KEY) ?? "null") as { p: string; x: string; t: string } | null;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(NOW);
    forgetServerTime();
  });
  afterEach(() => {
    clearDrafts();
    vi.useRealTimers();
  });

  it("writes once typing pauses for 250 ms, or at once when flushed", () => {
    savePolicyDraft("p-1", "{");
    expect(stored()).toBeNull();
    vi.advanceTimersByTime(POLICY_DEBOUNCE_MS - 1);
    expect(stored()).toBeNull();
    vi.advanceTimersByTime(1);
    expect(stored()?.t).toBe("{");
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    expect(stored()?.t).toBe("{}");
    // The client's sign-in path asks for a flush by the event the store listens for.
    savePolicyDraft("p-1", '{"a"}');
    window.dispatchEvent(new Event(FLUSH_DRAFTS));
    expect(stored()?.t).toBe('{"a"}');
  });

  it("lives thirty minutes from its last write, on the server's clock, refreshed by each write", () => {
    savePolicyDraft("p-1", "{");
    flushDrafts();
    expect(Date.parse(stored()?.x ?? "")).toBe(NOW + POLICY_LIFE_MS);
    vi.setSystemTime(NOW + 10 * 60_000);
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    expect(Date.parse(stored()?.x ?? "")).toBe(NOW + 10 * 60_000 + POLICY_LIFE_MS);
  });

  it("crosses a session's hard end into the next sign-in, for the same person alone", () => {
    const end = NOW + 2 * 60_000;
    // Written two minutes before the old session's hard end ...
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    // ... and read by a sign-in that completed five minutes after it.
    expect(restorePolicyDraft("p-1", end + 5 * 60_000)).toBe("{}");
    expect(restorePolicyDraft("p-2", end + 5 * 60_000)).toBeNull();
    // Refused to another person, it is gone for everyone.
    expect(restorePolicyDraft("p-1", end + 5 * 60_000)).toBeNull();
  });

  it("is not restored 31 minutes after its last write", () => {
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    expect(restorePolicyDraft("p-1", NOW + 31 * 60_000)).toBeNull();
    expect(stored()).toBeNull();
  });

  it("keeps nothing past 64 KB, and nothing for nobody", () => {
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    savePolicyDraft("p-1", "x".repeat(POLICY_LIMIT + 1024));
    flushDrafts();
    expect(stored()).toBeNull();
    savePolicyDraft(undefined, "{}");
    flushDrafts();
    expect(stored()).toBeNull();
  });

  it("leaves the editor working when storage refuses, keeping nothing", () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("refused");
    });
    savePolicyDraft("p-1", "{}");
    expect(() => {
      flushDrafts();
    }).not.toThrow();
    setItem.mockRestore();
    expect(stored()).toBeNull();
  });

  it("is forgotten on signing out, with any write still held", () => {
    savePolicyDraft("p-1", "{}");
    flushDrafts();
    savePolicyDraft("p-1", "{ }");
    clearDrafts();
    vi.advanceTimersByTime(POLICY_DEBOUNCE_MS);
    expect(stored()).toBeNull();
  });
});
