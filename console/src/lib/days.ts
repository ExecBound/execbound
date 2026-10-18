// SPDX-License-Identifier: AGPL-3.0-only
// Days and chart axes in the zone the viewer chose (#678): the day a run of rows belongs to,
// Home's chart labels and the viewer's most recent midnight. Apart from `lib/time.ts`, which
// prints instants, so a page that prints only instants (a cold approval link) does not load
// them. A string that is not an instant is returned as it came, and nothing here throws.

import type { Bucket } from "../api/types.gen";
import { localTime, readTimeZone, timeZoneId, type TimeZoneChoice, utcOffsetMinutes } from "./time";
import type { Range } from "./words";

function on(iso: string, choice: TimeZoneChoice, render: (date: string, weekday: string, day: string, minute: string) => string): string {
  const at = new Date(iso);
  if (iso === "" || Number.isNaN(at.getTime())) return iso;
  const local = localTime(at, timeZoneId(choice));
  return render(local.date, local.weekday, local.day, local.minute);
}

/** `Thu 2026-10-08`: the day a run of rows belongs to. */
export function dayHeading(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return on(iso, choice, (date, weekday) => `${weekday} ${date}`);
}

/** `2026-10-08`: which day an instant falls on in the chosen zone, so rows share a heading or not. */
export function dayKey(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return on(iso, choice, (date) => date);
}

/** `13:00`: a chart's hour axis, in the chosen zone. */
export function hourLabel(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return on(iso, choice, (_date, _weekday, _day, minute) => minute);
}

/** `Thu 8`: a chart's day axis, in the chosen zone. */
export function dayLabel(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return on(iso, choice, (_date, weekday, day) => `${weekday} ${day}`);
}

/** The viewer's most recent midnight in the chosen zone, as an instant. */
export function localMidnight(choice: TimeZoneChoice = readTimeZone(), at: Date = new Date()): Date {
  const midnight = Date.parse(`${localTime(at, timeZoneId(choice)).date}T00:00:00Z`);
  return new Date(midnight - utcOffsetMinutes(choice, at) * 60000);
}

/** The name of one chart column, for the description a screen reader reads. */
export function bucketName(range: Range, iso: string): string {
  if (range === "24h") return hourLabel(iso);
  if (range === "30d") return dayLabel(iso);
  return `${dayLabel(iso)} ${hourLabel(iso)}`;
}

const STEP_MS: Record<Range, number> = { "24h": 3_600_000, "7d": 21_600_000, "30d": 86_400_000 };

/**
 * The column labels of the chart: one every four hours over a day, one where each day begins
 * over a week, and every fifth day counting back from today over a month. The server starts a
 * week or a month at the viewer's midnight, so today is labelled. A bucket is dated by its
 * middle: across a daylight-saving change the buckets start an hour off midnight, and their
 * middles still fall on the right day.
 */
export function ticks(range: Range, series: Bucket[], choice: TimeZoneChoice = readTimeZone()): string[] {
  if (range === "24h") return series.map((bucket, index) => (index % 4 === 0 ? hourLabel(bucket.start, choice) : ""));
  const middles = series.map((bucket) => new Date(Date.parse(bucket.start) + STEP_MS[range] / 2).toISOString());
  if (range === "30d") return middles.map((middle, index) => ((middles.length - 1 - index) % 5 === 0 ? dayLabel(middle, choice) : ""));
  return middles.map((middle, index) => {
    const before = middles[index - 1];
    return before === undefined || dayKey(before, choice) !== dayKey(middle, choice) ? dayLabel(middle, choice) : "";
  });
}
