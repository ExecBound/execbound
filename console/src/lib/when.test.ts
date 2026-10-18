// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";

import { count, prefix, when } from "./when";

describe("times and identifiers", () => {
  it("shows a timestamp to the minute in the viewer's time zone, with the zone", () => {
    expect(when("2026-09-19T05:20:33.123456+00:00")).toBe("2026-09-19 05:20 UTC");
    expect(when("2026-09-19T07:05:00+02:00")).toBe("2026-09-19 05:05 UTC");
    expect(when("2026-09-19T05:20:00Z", "America/New_York")).toBe("2026-09-19 01:20 EDT");
    expect(when("2026-12-19T05:20:00Z", "America/New_York")).toBe("2026-12-19 00:20 EST");
    expect(when("2026-09-19T23:30:00Z", "Asia/Tokyo")).toBe("2026-09-20 08:30 GMT+9");
    expect(when("not a time")).toBe("not a time");
  });

  it("shows an identifier by its prefix and counts a noun", () => {
    expect(prefix("3446c357-35fe-4b4c-9911-af20f40e0445")).toBe("3446c357");
    expect(count(1, "session")).toBe("1 session");
    expect(count(2, "session")).toBe("2 sessions");
    expect(count(3, "dispatch", "dispatches")).toBe("3 dispatches");
  });
});
