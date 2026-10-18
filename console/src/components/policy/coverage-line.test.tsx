// SPDX-License-Identifier: AGPL-3.0-only
import { screen } from "@testing-library/react";
import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApprovalCoverage, CoverageAction } from "../../api/types.gen";
import { PLACEHOLDER, type SessionSummary } from "../../lib/session";
import { answerWith, renderPage, settle, type Seen } from "../../test/page";
import { ACTIVE, detail } from "../../test/policy";
import { BundleDetailView } from "./BundleDetail";

const SPACE = "77777777-7777-7777-7777-777777777777";
const NOW = "2026-10-11T12:00:00Z";
const ADMIN: SessionSummary = {
  ...PLACEHOLDER,
  role: "ADMIN",
  permissions: ["console.read", "access.manage", "workspace.manage", "policy.manage", "approvals.decide"],
};
// A policy manager holds no `access.manage`.
const MANAGER: SessionSummary = { ...PLACEHOLDER, role: "POLICY_MANAGER", permissions: ["console.read", "policy.manage"] };

const HELD: CoverageAction = {
  action: "endpoint.isolate",
  action_label: "Isolate endpoint",
  held_by: ["rule:review-production"],
  known: true,
  required: 1,
  upto: null,
  reviewers: 3,
  held_uncovered: { total: 2, rows: [] },
  requested_uncovered: { total: 0, rows: [] },
  thin: { total: 0, rows: [] },
};
const COVERAGE: ApprovalCoverage = {
  server_time: NOW,
  since: "2026-09-11T12:00:00Z",
  mode: "ENFORCE",
  truncated: false,
  spaces: [{ space_id: SPACE, name: "Production", bundle_id: ACTIVE, policy: "rules", actions: [HELD] }],
};

const REVIEWED = detail({
  rules: [
    { id: "review-production", action: "endpoint.isolate", effect: "REVIEW", sentence: "Review endpoint.isolate in production.", note: null },
    { id: "allow-workstations", action: "endpoint.isolate", effect: "ALLOW", sentence: "Allow endpoint.isolate when role is workstation.", note: null },
  ] as ReturnType<typeof detail>["rules"],
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function reads(seen: Seen[]): number {
  return seen.filter((call) => call.path === "/api/console/v1/approval-coverage").length;
}

describe("the policy page's coverage line (#678)", () => {
  it("says who can decide each review rule of the active policy, with its gaps and the way to fix them", async () => {
    answerWith({ "GET /api/console/v1/approval-coverage": { body: COVERAGE } });
    renderPage(<BundleDetailView detail={REVIEWED} active={{ bundle_id: ACTIVE }} />, ADMIN);
    const line = await screen.findByText(/3 people can decide this in Production/);
    expect(line).toHaveTextContent("2 held resources cannot be decided");
    expect(screen.getByRole("link", { name: "Approval rules" })).toHaveAttribute("href", "/approvers#coverage");
    // One line, under the review rule alone.
    expect(screen.getAllByText(/can decide this in/)).toHaveLength(1);
  });

  it("shows nothing and asks nothing on an inactive bundle or without access.manage", async () => {
    for (const [shown, session] of [
      [{ ...REVIEWED, active: false }, ADMIN],
      [REVIEWED, MANAGER],
    ] as const) {
      const seen = answerWith({ "GET /api/console/v1/approval-coverage": { body: COVERAGE } });
      const { unmount } = renderPage(<BundleDetailView detail={shown} active={{ bundle_id: ACTIVE }} />, session);
      await settle();
      expect(reads(seen)).toBe(0);
      expect(screen.queryByText(/can decide this in/)).toBeNull();
      unmount();
    }
  });

  it("is never read on a timer", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const seen = answerWith({ "GET /api/console/v1/approval-coverage": { body: COVERAGE } });
    renderPage(<BundleDetailView detail={REVIEWED} active={{ bundle_id: ACTIVE }} />, ADMIN);
    await screen.findByText(/3 people can decide this in Production/);
    await act(async () => { await vi.advanceTimersByTimeAsync(5 * 60_000); });
    expect(reads(seen)).toBe(1);
  });
});
