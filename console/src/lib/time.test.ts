// SPDX-License-Identifier: AGPL-3.0-only
import { act, render, renderHook, screen } from "@testing-library/react";
import { createElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Deadline, Time } from "../components/ui/Time";
import {
  ago,
  clock,
  deadline,
  instant,
  other,
  readTimeZone,
  relative,
  setDeviceZoneForTests,
  setTimeZone,
  timeZoneId,
  useTimeZone,
  utcOffsetMinutes,
  zoneName,
} from "./time";
import { dayHeading, dayKey, dayLabel, hourLabel, localMidnight } from "./days";

const SUMMER = "2026-10-08T17:34:24Z";
const WINTER = "2026-01-15T17:34:24Z";

beforeEach(() => {
  setDeviceZoneForTests("America/New_York");
});

afterEach(() => {
  vi.restoreAllMocks();
  setTimeZone("local");
  window.localStorage.clear();
  setDeviceZoneForTests(undefined);
});

describe("every form, in New York and in UTC", () => {
  it("prints an instant with its date, clock and zone", () => {
    expect(instant(SUMMER)).toBe("2026-10-08 13:34 EDT");
    expect(instant(SUMMER, "second")).toBe("2026-10-08 13:34:24 EDT");
    expect(instant(WINTER, "second")).toBe("2026-01-15 12:34:24 EST");
    expect(instant(SUMMER, "minute", "utc")).toBe("2026-10-08 17:34 UTC");
    expect(instant(SUMMER, "second", "utc")).toBe("2026-10-08 17:34:24 UTC");
  });

  it("reads the instants either side of a daylight-saving change in their own zone", () => {
    // Spring forward on 8 March 2026 at 07:00 UTC, fall back on 1 November at 06:00 UTC.
    expect(instant("2026-03-08T06:59:00Z")).toBe("2026-03-08 01:59 EST");
    expect(instant("2026-03-08T07:00:00Z")).toBe("2026-03-08 03:00 EDT");
    expect(instant("2026-11-01T05:59:00Z")).toBe("2026-11-01 01:59 EDT");
    expect(instant("2026-11-01T06:00:00Z")).toBe("2026-11-01 01:00 EST");
  });

  it("prints a clock, a day heading, a day key and the chart labels", () => {
    expect(clock(SUMMER)).toBe("13:34:24");
    expect(clock(SUMMER, "utc")).toBe("17:34:24");
    expect(dayHeading(SUMMER)).toBe("Thu 2026-10-08");
    expect(dayHeading("2026-10-09T02:00:00Z")).toBe("Thu 2026-10-08");
    expect(dayHeading("2026-10-09T02:00:00Z", "utc")).toBe("Fri 2026-10-09");
    expect(dayKey("2026-10-09T02:00:00Z")).toBe("2026-10-08");
    expect(dayKey("2026-10-09T02:00:00Z", "utc")).toBe("2026-10-09");
    expect(hourLabel("2026-10-08T17:00:00Z")).toBe("13:00");
    expect(hourLabel("2026-10-08T17:00:00Z", "utc")).toBe("17:00");
    expect(dayLabel(SUMMER)).toBe("Thu 8");
  });

  it("gives the other zone in the title, both ways", () => {
    expect(other(SUMMER)).toBe("2026-10-08 17:34:24 UTC");
    expect(other(SUMMER, "utc")).toBe("2026-10-08 13:34:24 EDT");
  });

  it("names the zone and resolves the choice", () => {
    expect(zoneName("utc")).toBe("UTC");
    expect(zoneName("local", new Date(SUMMER))).toBe("EDT");
    // At the spring-forward day's midnight the zone was still standard time.
    expect(zoneName("local", new Date("2026-03-08T05:00:00Z"))).toBe("EST");
    expect(timeZoneId("utc")).toBe("UTC");
    expect(timeZoneId("local")).toBe("America/New_York");
  });

  it("sends the offset at the viewer's most recent midnight, not now", () => {
    expect(utcOffsetMinutes("utc", new Date(SUMMER))).toBe(0);
    expect(utcOffsetMinutes("local", new Date(SUMMER))).toBe(-240);
    // 10:00 EDT on the spring-forward day: midnight was EST.
    expect(utcOffsetMinutes("local", new Date("2026-03-08T14:00:00Z"))).toBe(-300);
    expect(utcOffsetMinutes("local", new Date("2026-03-09T14:00:00Z"))).toBe(-240);
    // 10:00 EST on the fall-back day: midnight was EDT.
    expect(utcOffsetMinutes("local", new Date("2026-11-01T15:00:00Z"))).toBe(-240);
    expect(utcOffsetMinutes("local", new Date("2026-11-02T15:00:00Z"))).toBe(-300);
    setDeviceZoneForTests("Asia/Kathmandu");
    expect(utcOffsetMinutes("local", new Date(SUMMER))).toBe(345);
  });

  it("finds the viewer's most recent midnight, on a day the clocks change too", () => {
    expect(localMidnight("local", new Date("2026-03-08T14:00:00Z")).toISOString()).toBe("2026-03-08T05:00:00.000Z");
    expect(localMidnight("local", new Date("2026-11-01T15:00:00Z")).toISOString()).toBe("2026-11-01T04:00:00.000Z");
    expect(localMidnight("utc", new Date("2026-11-01T15:00:00Z")).toISOString()).toBe("2026-11-01T00:00:00.000Z");
  });
});

describe("ages, deadlines and distances", () => {
  it.each([
    [59, "59 s"],
    [60, "1 min"],
    [3599, "59 min"],
    [3600, "1 h"],
    [86399, "23 h"],
    [86400, "1 d"],
    [-5, "0 s"],
  ])("ages %i seconds as %s, rounding down", (seconds, words) => {
    expect(ago(seconds)).toBe(words);
  });

  const now = Date.parse("2026-10-08T17:00:00Z");
  it.each([
    [3600, "60 min left, by 14:00 EDT"],
    [61, "1 min left, by 13:01 EDT"],
    [59, "59 s left, by 13:00 EDT"],
    [1, "1 s left, by 13:00 EDT"],
    [0, "Lapsed at 13:00 EDT"],
    [-5, "Lapsed at 12:59 EDT"],
  ])("words a deadline %i seconds away", (seconds, words) => {
    expect(deadline(new Date(now + seconds * 1000).toISOString(), now)).toBe(words);
  });

  it("words a deadline in UTC when chosen", () => {
    expect(deadline("2026-10-08T17:04:00Z", now, "utc")).toBe("4 min left, by 17:04 UTC");
  });

  it.each([
    [59, "in 59 s"],
    [60, "in 1 min"],
    [3600, "in 1 h"],
    [86400 * 3, "in 3 d"],
    [-60, "1 min ago"],
    [-7200, "2 h ago"],
    [-86400, "1 d ago"],
  ])("words a distance of %i seconds", (seconds, words) => {
    expect(relative(new Date(now + seconds * 1000).toISOString(), now)).toBe(words);
  });

  it("returns anything that is not an instant as it came, and never throws", () => {
    for (const garbage of ["", "not a time", "2026-13-45T99:00:00Z", "<b>x</b>"]) {
      expect(instant(garbage)).toBe(garbage);
      expect(clock(garbage)).toBe(garbage);
      expect(other(garbage)).toBe(garbage);
      expect(dayHeading(garbage)).toBe(garbage);
      expect(dayKey(garbage)).toBe(garbage);
      expect(hourLabel(garbage)).toBe(garbage);
      expect(dayLabel(garbage)).toBe(garbage);
      expect(deadline(garbage, now)).toBe(garbage);
      expect(relative(garbage, now)).toBe(garbage);
    }
    expect(ago(Number.NaN)).toBe("0 s");
  });
});

describe("the setting", () => {
  it("is local by default and remembers UTC for this browser", () => {
    expect(readTimeZone()).toBe("local");
    setTimeZone("utc");
    expect(readTimeZone()).toBe("utc");
    expect(window.localStorage.getItem("eb.times")).toBe("utc");
    expect(instant(SUMMER)).toBe("2026-10-08 17:34 UTC");
    expect(utcOffsetMinutes()).toBe(0);
  });

  it("falls back to local when storage is absent", () => {
    vi.spyOn(window, "localStorage", "get").mockReturnValue(undefined as unknown as Storage);
    expect(readTimeZone()).toBe("local");
    expect(() => { setTimeZone("utc"); }).not.toThrow();
    // Nothing to remember it in: the console stays in the viewer's own zone.
    expect(readTimeZone()).toBe("local");
  });

  it("falls back to local when storage throws on read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    expect(readTimeZone()).toBe("local");
    expect(instant(SUMMER)).toBe("2026-10-08 13:34 EDT");
  });

  it("does not throw when storage refuses a write", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });
    expect(() => { setTimeZone("utc"); }).not.toThrow();
    expect(readTimeZone()).toBe("local");
  });

  it("follows a change made in another tab of the same browser", () => {
    const { result } = renderHook(() => useTimeZone());
    expect(result.current[0]).toBe("local");
    act(() => {
      window.localStorage.setItem("eb.times", "utc");
      window.dispatchEvent(new StorageEvent("storage", { key: "eb.times", newValue: "utc" }));
    });
    expect(result.current[0]).toBe("utc");
  });

  it("repaints every printed time when the choice changes", () => {
    const now = Date.parse("2026-10-08T17:30:00Z");
    render(createElement("div", null, createElement(Time, { at: SUMMER, precision: "second" }), createElement(Deadline, { at: "2026-10-08T17:34:00Z", now })));
    const stamp = screen.getByText("2026-10-08 13:34:24 EDT");
    expect(stamp.tagName).toBe("TIME");
    expect(stamp).toHaveAttribute("dateTime", SUMMER);
    expect(stamp).toHaveAttribute("title", "2026-10-08 17:34:24 UTC");
    expect(screen.getByText("4 min left, by 13:34 EDT")).toBeInTheDocument();
    act(() => { setTimeZone("utc"); });
    expect(screen.getByText("2026-10-08 17:34:24 UTC")).toHaveAttribute("title", "2026-10-08 13:34:24 EDT");
    expect(screen.getByText("4 min left, by 17:34 UTC")).toBeInTheDocument();
  });

  it("prints a clock in the form that asks for one, and a value that is not an instant as it came", () => {
    render(createElement("div", null, createElement(Time, { at: SUMMER, form: "clock" }), createElement(Time, { at: "not a time" })));
    expect(screen.getByText("13:34:24")).toHaveAttribute("title", "2026-10-08 17:34:24 UTC");
    expect(screen.getByText("not a time").tagName).toBe("SPAN");
  });
});
