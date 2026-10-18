// SPDX-License-Identifier: AGPL-3.0-only
// What a space refusal means to a person. The API answers a code from a closed list, never a
// sentence, so the copy lives here and a server string never reaches the page.
//
// Two different refusals share the `CONFLICT` code — a name already taken, and the assignment
// that would leave a tenant with no tenant administrator — because the code list is closed and
// neither is a new kind of failure. Which one a dialog can possibly have met is decided by
// which dialog it is: creating and renaming can only meet a taken name, archiving can only
// meet the tenant's last unarchived space, and assigning can only meet the last tenant
// administrator. Each dialog therefore passes the sentence its own `CONFLICT` means.

import { explain, refusalOf } from "../directory/errors";

/** One sentence for a refusal, with this dialog's own words for the codes it can meet. */
export function refusal(error: unknown, own: Record<string, string> = {}): string {
  if (error === null || error === undefined) return "";
  const sentence = own[refusalOf(error).code];
  return sentence ?? explain(error);
}

export const NAME_TAKEN = "A space of this tenant already has that name.";
export const LAST_SPACE = "This is the tenant's last space that is not archived; it stays.";
export const LAST_TENANT_ADMIN =
  "This tenant would be left with no tenant administrator. Somebody has to be able to act in every space.";

/** How a count reads beside its figure. */
export function plural(count: number, one: string, many = `${one}s`): string {
  return `${String(count)} ${count === 1 ? one : many}`;
}

/** A space's state in one word, for the table and the detail. */
export function state(archivedAt: string | null): "Active" | "Archived" {
  return archivedAt === null ? "Active" : "Archived";
}

/** A principal id shortened to its first block, as the directory pages shorten one. */
export function prefix(id: string): string {
  return id.slice(0, 8);
}

/** What a space role is called on screen. */
export const ROLES: Record<string, string> = {
  ADMIN: "Space administrator",
  HUMAN_APPROVER: "Approver",
};

/** What a space membership's narrowing means in words, said where the assignment is made. */
export const NARROWING =
  "A person with at least one space is a space member: they act in the spaces they are assigned and nowhere else. Giving a tenant administrator their first space narrows them to it.";
