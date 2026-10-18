// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { isQuietConnection, isQuietSource } from "./quiet";

describe("what quiet means (MQ3, #678)", () => {
  it("is an overdue connection, never one that is only not reporting", () => {
    expect(isQuietConnection({ revoked_at: null, overdue_since: "2026-09-19T05:00:00+00:00" })).toBe(true);
    expect(isQuietConnection({ revoked_at: null, overdue_since: null })).toBe(false);
    expect(isQuietConnection({ revoked_at: "2026-09-19T05:00:00+00:00", overdue_since: "2026-09-19T05:00:00+00:00" })).toBe(false);
  });

  it("is a stale source, never a disabled, expired or never-heard one", () => {
    expect(isQuietSource({ revoked_at: null, health_state: "STALE", coverage: "Stale" })).toBe(true);
    expect(isQuietSource({ revoked_at: null, health_state: "REPORTING", coverage: "Reporting" })).toBe(false);
    expect(isQuietSource({ revoked_at: null, health_state: "STALE", coverage: "Disabled" })).toBe(false);
    expect(isQuietSource({ revoked_at: null, health_state: "NEVER_SEEN", coverage: "Expired" })).toBe(false);
    expect(isQuietSource({ revoked_at: null, health_state: "NEVER_SEEN", coverage: "No heartbeat" })).toBe(false);
    expect(isQuietSource({ revoked_at: "2026-09-19T05:00:00+00:00", health_state: "STALE", coverage: "Disabled" })).toBe(false);
  });
});
