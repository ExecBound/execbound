// SPDX-License-Identifier: AGPL-3.0-only
// How the directory pages print identifiers and times: an id as its eight-character prefix,
// a time as its minute in the zone the viewer chose with the zone named, an agent or a key by
// its counting number, and a person by label, email or number. Every value is text; nothing
// here builds a link or a query.

import { dayKey } from "../../lib/days";
import { instant } from "../../lib/time";
import { handle, type Noun, prefix } from "./handles";

export {
  handle,
  noun,
  prefix,
  refHandle,
  refName,
  SCHEDULER,
  type Noun,
  type PrincipalLike,
} from "./handles";

/** The expiry an API key issued to never expire carries: `identity.NEVER` on the server. */
const NEVER = Date.UTC(9999, 11, 31);

/** A key's expiry: "Never" for one issued to never expire, in whatever offset it arrives. */
export function expiry(iso: string): string {
  return new Date(iso).getTime() >= NEVER ? "Never" : when(iso);
}

/** An ISO timestamp as `YYYY-MM-DD HH:MM` and the zone, in the viewer's time zone, or the
 * fallback for nothing. */
export function when(iso: string | null | undefined, fallback = "never"): string {
  if (iso === null || iso === undefined || iso === "") return fallback;
  const moment = new Date(iso);
  if (Number.isNaN(moment.getTime())) return fallback;
  return instant(iso, "minute");
}

/** An ISO timestamp as its date alone, in the chosen zone. */
export function day(iso: string | null | undefined, fallback = "never"): string {
  if (iso === null || iso === undefined || iso === "") return fallback;
  if (Number.isNaN(new Date(iso).getTime())) return fallback;
  return dayKey(iso);
}

/** `HUMAN_APPROVER` as `human approver`, and so on, for a kind shown in a sentence. */
export function words(value: string | null | undefined): string {
  return (value ?? "").replaceAll("_", " ").toLowerCase();
}

/** A count with its noun, `1 approver` or `2 approvers`. */
export function plural(count: number, one: string, many = `${one}s`): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

/** An agent the directory discovered and no principal backs: it has no counting number, so it
 * is never "Agent N"; its display name, else "Discovered agent 3f2504e0". */
export function discoveredName(displayName: string | null | undefined, rowId: string): string {
  return displayName !== null && displayName !== undefined && displayName !== ""
    ? displayName
    : `Discovered agent ${prefix(rowId)}`;
}

/** A principal as a person reads it: its label; else the email it signs in with, which only a
 * person has; else its handle, "Agent 3" or "User 3". */
export function principalName(
  of: Noun,
  label: string | null | undefined,
  number: number | null | undefined,
  id?: string | null,
  email?: string | null,
): string {
  if (label !== null && label !== undefined && label !== "") return label;
  if (email !== null && email !== undefined && email !== "") return email;
  return handle(of, number, id);
}

/** A name with its handle after it, "Dana Reyes · User 3", or the handle alone when that is
 * the name: for text that cannot hold markup, such as a select's option. */
export function withHandle(name: string, tag: string): string {
  return name === tag ? name : `${name} · ${tag}`;
}

/** An API key as a person reads it: "Key 12". A person's credential has no number, so its prefix. */
export function keyName(number: number | null | undefined, id: string): string {
  return number !== null && number !== undefined ? `Key ${String(number)}` : prefix(id);
}
