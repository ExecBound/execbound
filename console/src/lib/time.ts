// SPDX-License-Identifier: AGPL-3.0-only
// The one place the console turns an instant into text (#678). An instant reads
// `2026-10-08 13:34 EDT` in the zone the viewer chose: their own time zone, unless they picked
// UTC under My account → Appearance. Every printed time names its zone, or sits under a
// heading or caption that does, and its title gives the same instant in the other zone.
//
// Every form is built from `formatToParts` with the "en-US" locale, so the output does not
// depend on the browser's language. A string that is not an instant is returned as it came,
// and nothing here throws. The choice is per browser, kept in localStorage under `eb.times`;
// storage that is missing or refuses means "local", and nothing about it reaches the server
// except the offset the console sends with the reads that count "today".

import { useSyncExternalStore } from "react";

export type TimeZoneChoice = "local" | "utc";

const KEY = "eb.times";

const FIELDS: Intl.DateTimeFormatOptions = {
  weekday: "short",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZoneName: "short",
};

// ---------------------------------------------------------------------------------------------
// The setting

const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

/** The viewer's choice; "local" when nothing is stored or storage cannot be read. */
export function readTimeZone(): TimeZoneChoice {
  try {
    return window.localStorage.getItem(KEY) === "utc" ? "utc" : "local";
  } catch {
    return "local";
  }
}

/** Choose a zone for this browser. Storage that refuses leaves the console in the viewer's own
 * zone, and nothing fails. */
export function setTimeZone(choice: TimeZoneChoice): void {
  try {
    window.localStorage.setItem(KEY, choice);
  } catch {
    // Nothing to remember the choice in.
  }
  notify();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Another tab of the same browser changed the choice: follow it.
  const onStorage = (event: StorageEvent) => {
    if (event.key === KEY || event.key === null) listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/** The choice and a setter; every component that prints a time repaints when it changes. */
export function useTimeZone(): [TimeZoneChoice, (choice: TimeZoneChoice) => void] {
  const choice = useSyncExternalStore(subscribe, readTimeZone, () => "local" as const);
  return [choice, setTimeZone];
}

// ---------------------------------------------------------------------------------------------
// Zones

let deviceOverride: string | undefined;

/**
 * Replace the device's zone for every formatter until called again with `undefined`. Vitest
 * runs with TZ=UTC, where a local time labelled UTC cannot be seen; this lets a test read the
 * console as a viewer in New York would. Production code never calls it, and lint refuses the
 * call outside test files.
 */
export function setDeviceZoneForTests(zone: string | undefined): void {
  deviceOverride = zone;
  notify();
}

function deviceZone(): string {
  return deviceOverride ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** The IANA zone a choice resolves to: the device's (or the test seam's), or "UTC". */
export function timeZoneId(choice: TimeZoneChoice = readTimeZone()): string {
  return choice === "utc" ? "UTC" : deviceZone();
}

const formats = new Map<string, Intl.DateTimeFormat>();

function format(timeZone: string): Intl.DateTimeFormat {
  let found = formats.get(timeZone);
  if (found === undefined) {
    found = new Intl.DateTimeFormat("en-US", { ...FIELDS, timeZone });
    formats.set(timeZone, found);
  }
  return found;
}

/** A moment's date, clock and zone name in the viewer's time zone, or in `timeZone` if given. */
export interface LocalTime {
  date: string;
  minute: string;
  second: string;
  zone: string;
  weekday: string;
  day: string;
}

export function localTime(moment: Date, timeZone: string = deviceZone()): LocalTime {
  // Every field FIELDS names is in the parts, so each is read as present.
  const part = {} as Record<Intl.DateTimeFormatPartTypes, string>;
  for (const item of format(timeZone).formatToParts(moment)) part[item.type] = item.value;
  const minute = `${part.hour}:${part.minute}`;
  return {
    date: `${part.year}-${part.month}-${part.day}`,
    minute,
    second: `${minute}:${part.second}`,
    zone: part.timeZoneName,
    weekday: part.weekday,
    day: String(Number(part.day)),
  };
}

/** The wall clock of `ms` in a zone, read as if it were UTC: its distance from `ms` is the
 * zone's offset. */
function wall(ms: number, timeZone: string): number {
  const local = localTime(new Date(ms), timeZone);
  return Date.parse(`${local.date}T${local.second}Z`);
}

/** The zone's distance east of UTC at one instant, in whole minutes. */
function offsetAt(ms: number, timeZone: string): number {
  return Math.round((wall(ms, timeZone) - Math.floor(ms / 1000) * 1000) / 60000);
}

/** "EDT" or "UTC": the short name of the chosen zone at `at`. */
export function zoneName(choice: TimeZoneChoice = readTimeZone(), at: Date = new Date()): string {
  return choice === "utc" ? "UTC" : localTime(at, timeZoneId(choice)).zone;
}

/**
 * The chosen zone's offset in minutes east of UTC at the viewer's most recent local midnight,
 * not now: on the day clocks change, the server's "today" then starts at the midnight that
 * really happened. 0 for UTC.
 */
export function utcOffsetMinutes(choice: TimeZoneChoice = readTimeZone(), at: Date = new Date()): number {
  if (choice === "utc" || Number.isNaN(at.getTime())) return 0;
  const zone = timeZoneId(choice);
  const midnight = Date.parse(`${localTime(at, zone).date}T00:00:00Z`);
  const guess = midnight - offsetAt(at.getTime(), zone) * 60000;
  return offsetAt(midnight - offsetAt(guess, zone) * 60000, zone) || 0;
}

// ---------------------------------------------------------------------------------------------
// Forms

function parse(iso: string): Date | null {
  const moment = new Date(iso);
  return iso === "" || Number.isNaN(moment.getTime()) ? null : moment;
}

/** Whether a string is an instant the formatters will print. */
export function isInstant(iso: string): boolean {
  return parse(iso) !== null;
}

/** One form of an instant in the chosen zone; a string that is not an instant, as it came. */
function form(iso: string, choice: TimeZoneChoice, render: (local: LocalTime) => string): string {
  const moment = parse(iso);
  return moment === null ? iso : render(localTime(moment, timeZoneId(choice)));
}

/** `2026-10-08 13:34 EDT`, or with seconds where the second is evidence. */
export function instant(iso: string, precision: "minute" | "second" = "minute", choice: TimeZoneChoice = readTimeZone()): string {
  return form(iso, choice, (local) => `${local.date} ${precision === "second" ? local.second : local.minute} ${local.zone}`);
}

/** `13:34:24`, only inside a list whose heading, column or caption names the zone. */
export function clock(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return form(iso, choice, (local) => local.second);
}

/**
 * `13:34:24` for an instant on the viewer's today and `2026-10-08 13:34:24` for any other day,
 * in the chosen zone, only inside a list whose heading, column or caption names the zone: a row
 * from an earlier day never reads as today's (#678). `nowMs` is the server's time.
 */
export function listed(iso: string, nowMs: number, choice: TimeZoneChoice = readTimeZone()): string {
  const zone = timeZoneId(choice);
  return form(iso, choice, (local) =>
    local.date === localTime(new Date(nowMs), zone).date ? local.second : `${local.date} ${local.second}`,
  );
}

/** The same instant in the zone not chosen, to the second: the title of every printed time. */
export function other(iso: string, choice: TimeZoneChoice = readTimeZone()): string {
  return instant(iso, "second", choice === "utc" ? "local" : "utc");
}

/** `40 s`, `6 min`, `2 h`, `3 d`: one rounding (down) for every age. */
export function ago(seconds: number): string {
  const whole = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0;
  const [size, unit] = whole < 60 ? [1, "s"] : whole < 3600 ? [60, "min"] : whole < 86400 ? [3600, "h"] : [86400, "d"];
  return `${String(Math.floor(whole / size))} ${unit}`;
}

/**
 * `4 min left, by 13:39 EDT`, `40 s left, by 13:39 EDT`, or `Lapsed at 13:39 EDT`. `nowMs` is
 * the server's time (`serverNow()`), so a wrong device clock never moves a deadline.
 */
export function deadline(iso: string, nowMs: number, choice: TimeZoneChoice = readTimeZone()): string {
  return form(iso, choice, (local) => {
    const by = `${local.minute} ${local.zone}`;
    const left = Math.floor((Date.parse(iso) - nowMs) / 1000);
    return left > 0 ? `${left >= 60 ? `${String(Math.floor(left / 60))} min` : `${String(left)} s`} left, by ${by}` : `Lapsed at ${by}`;
  });
}

/** `in 6 h`, `in 3 d`, `2 h ago`: a time whose distance matters more than its clock. */
export function relative(iso: string, nowMs: number): string {
  const moment = parse(iso);
  if (moment === null) return iso;
  const seconds = Math.floor((moment.getTime() - nowMs) / 1000);
  return seconds >= 0 ? `in ${ago(seconds)}` : `${ago(-seconds)} ago`;
}
