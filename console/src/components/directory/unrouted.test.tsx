// SPDX-License-Identifier: AGPL-3.0-only
import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { UnroutedApprovals } from "../../api/types.gen";
import { POLL_MS } from "../../lib/poll";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { answerWith, renderPage, settle, type Seen } from "../../test/page";
import { UnroutedNotice } from "./UnroutedNotice";

const NOW = "2026-10-11T12:00:00Z";
const EXECUTION = "7c21e04b-0000-4000-8000-000000000001";
const SPACE = "22222222-2222-2222-2222-222222222222";
const RECORD = {
  approval_id: "9a11e04b-0000-4000-8000-000000000002",
  execution_id: EXECUTION,
  request_ref: "EB-20",
  space_id: SPACE,
  at: NOW,
  state: "PENDING",
};
const NONE: UnroutedApprovals = {
  server_time: NOW,
  pending: 0,
  pending_nobody: 0,
  pending_truncated: false,
  pending_latest: null,
  recent: 0,
  recent_latest: null,
};

const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"],
};
const APPROVER: SessionSummary = { ...PLACEHOLDER, role: "APPROVER", permissions: ["console.read", "approvals.decide"] };
// An administrator narrowed to Spaces holds no workspace-wide `access.manage`.
const NARROWED: SessionSummary = { ...PLACEHOLDER, role: "ADMIN", permissions: ["console.read", "approvals.decide", "policy.manage"] };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function reads(seen: Seen[]): number {
  return seen.filter((call) => call.path === "/api/console/v1/approval-coverage/unrouted").length;
}

function mount(body: UnroutedApprovals, session: SessionSummary = ADMIN) {
  const seen = answerWith({ "GET /api/console/v1/approval-coverage/unrouted": { body } });
  renderPage(<UnroutedNotice />, session);
  return seen;
}

describe("the unrouted line", () => {
  it("says no one can approve when nobody can decide any of them", async () => {
    mount({ ...NONE, pending: 2, pending_nobody: 2, pending_latest: RECORD });
    expect(await screen.findByText(/No one can approve 2 held requests\./)).toBeInTheDocument();
    const record = screen.getByRole("link", { name: "EB-20" });
    expect(record).toHaveAttribute("href", `/activity?open=${EXECUTION}`);
    expect(screen.getByRole("link", { name: "Choose reviewers" })).toHaveAttribute("href", "/approvers#coverage");
  });

  it("names a quorum shortfall when some can decide but too few", async () => {
    mount({ ...NONE, pending: 2, pending_nobody: 1, pending_latest: RECORD });
    expect(
      await screen.findByText(/2 held requests cannot reach their quorum: fewer people can decide them than they need\./),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "EB-20" })).toBeInTheDocument();
  });

  it("speaks of the last seven days when nothing is waiting now", async () => {
    mount({ ...NONE, recent: 3, recent_latest: { ...RECORD, state: "EXPIRED" } });
    expect(
      await screen.findByText(/In the last 7 days, 3 held requests had fewer people who could decide them than they need\./),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "EB-20" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Choose reviewers" })).toBeInTheDocument();
  });

  it("renders nothing with nothing to report", async () => {
    const seen = mount(NONE);
    await settle();
    expect(reads(seen)).toBe(1);
    expect(screen.queryByText(/held request/)).toBeNull();
    expect(screen.queryByRole("link", { name: "Choose reviewers" })).toBeNull();
  });

  it("makes no call for an approver or an administrator narrowed to Spaces", async () => {
    for (const session of [APPROVER, NARROWED]) {
      const seen = mount({ ...NONE, pending: 1, pending_nobody: 1, pending_latest: RECORD }, session);
      await settle();
      expect(reads(seen)).toBe(0);
      expect(screen.queryByText(/No one can approve/)).toBeNull();
    }
  });

  it("rides the shared timer and asks for nothing while the tab is hidden", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const seen = mount(NONE);
    try {
      await vi.waitFor(() => { expect(reads(seen)).toBe(1); });
      await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS); });
      await vi.waitFor(() => { expect(reads(seen)).toBe(2); });
      Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
      await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS * 4); });
      expect(reads(seen)).toBe(2);
    } finally {
      Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    }
  });
});
