// SPDX-License-Identifier: AGPL-3.0-only
// What a browser keeps for the palette's Recent group (NV11, #678): kinds and identifiers only,
// keyed by tenant and principal, read back strictly, and nothing at all where storage fails.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readApprovalQueryKey } from "../api/@tanstack/react-query.gen";
import { detail, item } from "../approvals/fixtures";
import { allEntries } from "../shell/navigation";
import { clearRecents, readRecents, recordRecent, RECENT_MAX, useRecordRecents } from "./recents";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "./session";

const UUID = "5c2f91d3-0000-4000-8000-000000000002";
const APPROVAL = "4b1e90c2-0000-4000-8000-000000000001";
const PATHS = new Set(allEntries().map((entry) => entry.to));
const ME = { tenant: "t1", principal: "p1" };

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("the recent list (NV11, #678)", () => {
  it("keeps only a kind and an id, under the tenant and the principal", () => {
    recordRecent(ME, { k: "execution", id: UUID }, PATHS);
    recordRecent(ME, { k: "page", to: "/agents" }, PATHS);
    const stored: unknown = JSON.parse(window.localStorage.getItem("eb.recent.v1.t1.p1") ?? "null");
    expect(stored).toEqual([
      { k: "page", to: "/agents" },
      { k: "execution", id: UUID },
    ]);
    for (const entry of stored as Record<string, unknown>[]) {
      expect(Object.keys(entry).sort()).toEqual(entry.k === "page" ? ["k", "to"] : ["id", "k"]);
    }
  });

  it("shows another person or another workspace nothing", () => {
    recordRecent(ME, { k: "execution", id: UUID }, PATHS);
    expect(readRecents({ tenant: "t1", principal: "p2" }, PATHS)).toEqual([]);
    expect(readRecents({ tenant: "t2", principal: "p1" }, PATHS)).toEqual([]);
    expect(readRecents(ME, PATHS)).toEqual([{ k: "execution", id: UUID }]);
  });

  it.each([
    [{ k: "page", to: "https://evil.example" }],
    [{ k: "execution", id: "not-a-uuid" }],
    [{ k: "approval", id: UUID }],
    [{ k: "execution", id: UUID, label: "ws-01.corp.example" }],
    ["text"],
  ])("discards a tampered list holding %j", (bad) => {
    window.localStorage.setItem("eb.recent.v1.t1.p1", JSON.stringify([{ k: "page", to: "/agents" }, bad]));
    expect(readRecents(ME, PATHS)).toEqual([]);
  });

  it("keeps the newest eight, without duplicates", () => {
    const ids = Array.from({ length: 9 }, (_, index) => `5c2f91d3-0000-4000-8000-${String(index).padStart(12, "0")}`);
    for (const id of ids) recordRecent(ME, { k: "execution", id }, PATHS);
    recordRecent(ME, { k: "execution", id: ids[8] ?? "" }, PATHS);
    const kept = readRecents(ME, PATHS);
    expect(kept).toHaveLength(RECENT_MAX);
    expect(kept[0]).toEqual({ k: "execution", id: ids[8] });
    expect(kept.map((entry) => (entry.k === "execution" ? entry.id : entry.to))).not.toContain(ids[0]);
    clearRecents(ME);
    expect(readRecents(ME, PATHS)).toEqual([]);
  });

  it("throws nothing and keeps nothing where storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(() => {
      recordRecent(ME, { k: "execution", id: UUID }, PATHS);
    }).not.toThrow();
    expect(readRecents(ME, PATHS)).toEqual([]);
  });

  it("keeps nothing without a tenant or a principal", () => {
    recordRecent({ tenant: "t1" }, { k: "execution", id: UUID }, PATHS);
    recordRecent({ principal: "p1" }, { k: "execution", id: UUID }, PATHS);
    expect(window.localStorage.length).toBe(0);
  });
});

describe("recording what a person opens (NV11, #678)", () => {
  const session: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", tenant: { id: "t1", name: "Acme", detail: "" }, person: { label: "A", detail: "", initials: "", id: "p1" } };

  function hook(pathname: string, open: string | undefined, client: QueryClient) {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>
        <SessionContext.Provider value={session}>{children}</SessionContext.Provider>
      </QueryClientProvider>
    );
    return renderHook(({ path, record }: { path: string; record: string | undefined }) => {
      useRecordRecents(path, record);
    }, { wrapper, initialProps: { path: pathname, record: open } });
  }

  it("records an approval as its execution once its read is in the cache, and asks for nothing", () => {
    const fetched = vi.fn();
    vi.stubGlobal("fetch", fetched);
    const client = new QueryClient();
    hook(`/approvals/${APPROVAL}`, undefined, client);
    expect(readRecents(ME, PATHS)).toEqual([]);
    expect(fetched).not.toHaveBeenCalled();
    const client2 = new QueryClient();
    client2.setQueryData(readApprovalQueryKey({ path: { approval_id: APPROVAL } }), detail({ item: item({ execution_id: UUID }) }));
    hook(`/approvals/${APPROVAL}`, undefined, client2);
    expect(readRecents(ME, PATHS)).toEqual([{ k: "execution", id: UUID }]);
    expect(fetched).not.toHaveBeenCalled();
  });

  it("records a record open over Activity as itself, and a person's page as Users", () => {
    const client = new QueryClient();
    const { rerender } = hook("/activity", UUID, client);
    expect(readRecents(ME, PATHS)[0]).toEqual({ k: "execution", id: UUID });
    rerender({ path: "/people/d0000000-0000-4000-8000-000000000004", record: undefined });
    expect(readRecents(ME, PATHS)[0]).toEqual({ k: "page", to: "/people" });
  });
});
