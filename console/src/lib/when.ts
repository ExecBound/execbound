// SPDX-License-Identifier: AGPL-3.0-only
// Times and identifiers as the console shows them: a timestamp as `2026-09-19 01:20 EDT` in
// the zone the viewer chose (lib/time.ts formats it), an identifier by its first eight
// characters, both in Plex Mono where they appear. Every value here is data the server sent;
// nothing is parsed into markup.

import { instant, localTime } from "./time";

export { localTime } from "./time";
export type { LocalTime } from "./time";

/** A timestamp to the minute in the chosen zone, or in `timeZone` if given; a string that is
 * not a time is shown as it came. */
export function when(iso: string, timeZone?: string): string {
  if (timeZone === undefined) return instant(iso, "minute");
  const moment = new Date(iso);
  if (Number.isNaN(moment.getTime())) return iso;
  const local = localTime(moment, timeZone);
  return `${local.date} ${local.minute} ${local.zone}`;
}

/** The first eight characters of an identifier, as the pages show them. */
export function prefix(id: string): string {
  return id.slice(0, 8);
}

/** "1 session" or "3 sessions". */
export function count(value: number, noun: string, plural = `${noun}s`): string {
  return `${String(value)} ${value === 1 ? noun : plural}`;
}
