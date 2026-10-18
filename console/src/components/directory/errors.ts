// SPDX-License-Identifier: AGPL-3.0-only
// What a refusal of the console API means to a person (#333): the API answers a
// code from a closed list and, for a body fault, the fields at fault; the copy lives here,
// never in the response, so a server string never reaches the page. A field this form has no
// copy for is still named, but only when it reads like a schema path (`FIELD_PATH` below):
// anything else falls back to the generic line, so an unbounded or malformed value the server
// sent as a "field" is never the server string this file exists to keep off the page.

export interface Refusal {
  code: string;
  fields: string[];
}

const FALLBACK = "ExecBound is unavailable; try again shortly.";

/** The agent limit's one sentence (#257), declared once and read into `COPY` below so a
 * person sees the same words for the same fact wherever they meet it: the refusal toast a
 * failed creation shows, and the Agents page's capacity line when the workspace is already at
 * or over its limit. Kept as its own `string`-typed constant (not `COPY.PLAN_LIMIT`) because
 * `COPY`'s index signature would type a lookup `string | undefined` under
 * `noUncheckedIndexedAccess`, which the capacity line's template literal can't take. */
export const PLAN_LIMIT_SENTENCE =
  "This workspace has reached its agent limit. Every agent you have keeps running.";

/** An entry a re-invitation replaced (migration 0061) is retired for good. Declared once for
 * the same reason as `PLAN_LIMIT_SENTENCE`: the refusal a Reactivate attempt shows and the
 * person page's own note say the same words for the same fact. */
export const PRINCIPAL_REPLACED_SENTENCE =
  "This person rejoined through an invitation and now has a new entry in this workspace. Manage their access there.";

const COPY: Record<string, string> = {
  GROUP_IN_USE: "Remove group members and roles, then disable its approval rules before deleting it.",
  INVALID_REQUEST: "The request was not understood.",
  INVALID_BODY: "Something in the form is missing or out of bounds.",
  SESSION_REQUIRED: "Sign in to continue.",
  MFA_REQUIRED: "This change was not made. Try again, and enter a code when ExecBound asks you to verify your identity.",
  DIRECTORY_REQUIRED: "Use your workspace's organization sign-in to continue.",
  TOKEN_NOT_ALLOWED: "A personal access token can't do this. Sign in to the console to do it.",
  TOO_MANY_TOKENS: "You already have ten active tokens. Revoke one to create another.",
  WORKSPACE_CHANGED: "The workspace changed. Reload before continuing.",
  FORBIDDEN: "This is not yours to do.",
  INVALID_CSRF: "This page is out of date; reload it and try again.",
  INVALID_ORIGIN: "The request came from somewhere else.",
  INVALID_PRINCIPAL: "That principal cannot be changed from here.",
  NOT_FOUND: "There is nothing here.",
  METHOD_NOT_ALLOWED: "The request was not understood.",
  CONFLICT: "Something changed first; the page shows what is there now.",
  TOO_LARGE: "The form is too large.",
  UNSUPPORTED_MEDIA_TYPE: "The request was not understood.",
  STOPPED: "The tenant is stopped.",
  SPACE_ARCHIVED: "This space takes no new work; unarchive it first.",
  SPACE_REQUIRED: "Choose an active Space for this item, then try again. Your entries have been kept.",
  SIGNAL_MAPPING_ONLY: "An action in this file is served in this Space only by a signal mapping, which a rules file cannot carry. Paste the complete bundle under Advanced instead, or ask your operator.",
  MAPPINGS_CONFLICT: "Two mappings for an action in this file cannot share one policy. Ask your operator to choose one with ruleset-compile --ref, then paste the bundle it prints.",
  LAST_ADMIN: "Assign another active workspace Administrator before removing this access.",
  PLAN_LIMIT: PLAN_LIMIT_SENTENCE,
  SAMPLES_NOT_OFFERED: "Sample targets are offered only to a workspace with no policy and no connections.",
  SAMPLES_BUSY: "A sample request is waiting for approval or provider evidence. Settle it before removing the samples.",
  SAMPLES_UNAVAILABLE: "Sample targets are not available on this deployment.",
  TOO_MANY_REQUESTS: "Too many requests; try again shortly.",
  UNAVAILABLE: FALLBACK,
  INVITATION_PENDING: "There is already a pending invitation for that address.",
  ALREADY_MEMBER: "That address already belongs to someone in this workspace.",
  RESEND_LIMIT: "This invitation cannot be resent again yet.",
  PRINCIPAL_REPLACED: PRINCIPAL_REPLACED_SENTENCE,
};

/** What each field of a directory form needs, said once. Label, reason, name, email and
 * description are each screened for text shaped like a password, key or token where they are
 * written, so their sentence says that rule beside the one it always stated; a value that
 * merely stood outside the old rule and one that reads as a credential are refused the same
 * way and need the same sentence. */
export const FIELDS: Record<string, string> = {
  label: "A label of 1 to 80 characters is required, with nothing in it that looks like a password, key or token.",
  reason: "A reason of 1 to 500 characters is required, with nothing in it that looks like a password, key or token.",
  lifetime: "Choose a lifetime from the list.",
  target: "Choose a canonical target from the list.",
  action: "Choose an action from the catalog.",
  approver: "Choose an approver from the list.",
  principal: "Choose a principal from the list.",
  kind: "Choose a kind from the list.",
  // A name already taken is answered as `CONFLICT`, never `INVALID_BODY`, so this sentence
  // states only what this code can mean: a bound or a credential shape.
  name: "A name of 1 to 80 characters is required, with nothing in it that looks like a password, key or token.",
  detail: "A detail line of at most 160 characters is allowed.",
  role: "A space role narrows and never raises: only an administrator may hold the administrator role in a space.",
  email: "Enter a valid email address whose domain does not look like a password, key or token.",
  grants: "Choose a role and, unless it is Administrator, a Space.",
  reviewer_group_id:
    "That reviewer group grants more than this invitation, or is no longer in this workspace. Choose another group, or none.",
  description: "A description of at most 240 characters is allowed, with nothing in it that looks like a password, key or token.",
};

/** A server field name is rendered only when it reads like a schema path: dotted segments of
 * letters, digits and underscores, each starting with a letter or underscore, and short
 * enough that the sentence stays a sentence. A bundle location such as
 * `ruleset.rules.0.note` matches; anything odd or unbounded does not, and falls back to the
 * generic line exactly as no field at all would. */
const FIELD_PATH = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/;
const FIELD_NAME_MAX = 120;

function looksLikeAField(field: string): boolean {
  return field.length <= FIELD_NAME_MAX && FIELD_PATH.test(field);
}

/** The refusal a thrown value carries; anything else reads as unavailability. */
export function refusalOf(error: unknown): Refusal {
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") {
    const fields =
      "fields" in error && Array.isArray(error.fields)
        ? error.fields.filter((field): field is string => typeof field === "string")
        : [];
    return { code: error.code, fields };
  }
  return { code: "UNAVAILABLE", fields: [] };
}

/** One sentence for a refusal, naming the fields at fault when the body was the problem. A
 * field this form has no copy for, such as a policy bundle location (`ruleset.rules.0.note`),
 * is still named rather than answered with the generic line, because it may be exactly that
 * location's own text read as a password, key or token; but only when the field itself reads
 * like a schema path (`looksLikeAField`), never when it looks like something else entirely. */
export function explain(error: unknown): string {
  const refusal = refusalOf(error);
  if (refusal.code === "INVALID_BODY") {
    const named = refusal.fields.map((field) => FIELDS[field]).filter((copy) => copy !== undefined);
    if (named.length > 0) return named.join(" ");
    const safe = refusal.fields.filter(looksLikeAField);
    if (safe.length > 0) {
      return `Check ${safe.join(", ")}: something there is missing, out of bounds, or looks like a password, key or token.`;
    }
  }
  return COPY[refusal.code] ?? FALLBACK;
}
