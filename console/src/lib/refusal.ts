// SPDX-License-Identifier: AGPL-3.0-only
// A refusal from the console API is JSON with a code from a closed list, and the client maps
// the code to copy (#333). The generated client throws the parsed body; anything
// else that reaches a page (a network failure, an answer that is not JSON) reads as
// unavailable, and no server string is ever shown.

export interface Refusal {
  code: string;
  /** The body fields a refusal named, for a form to mark. */
  fields: string[];
}

const COPY = {
  INVALID_REQUEST: "The request was not understood.",
  INVALID_BODY: "A field is missing, unknown or out of bounds.",
  SESSION_REQUIRED: "Your session ended. Sign in again.",
  MFA_REQUIRED: "This change was not made. Try again, and enter a code when ExecBound asks you to verify your identity.",
  FORBIDDEN: "This is not yours to do.",
  INVALID_CSRF: "The request did not carry your session's token. Reload the page and try again.",
  INVALID_ORIGIN: "The request came from somewhere else.",
  NOT_FOUND: "There is nothing here.",
  METHOD_NOT_ALLOWED: "This address does not take that method.",
  CONFLICT: "That is already the current state; nothing was changed.",
  TOO_LARGE: "The request is too large.",
  UNSUPPORTED_MEDIA_TYPE: "The request was not understood.",
  STOPPED: "The emergency stop is active; nothing was changed.",
  ASSISTANT_OFF: "The assistant is not turned on for this workspace. An administrator turns it on in Workspace settings.",
  INVALID_PROPOSAL: "The assistant could not draft that rule.",
  TOO_MANY_REQUESTS: "Too many requests; try again shortly.",
  UNAVAILABLE: "ExecBound is unavailable; nothing was changed. Try again shortly.",
} as const satisfies Record<string, string>;

const FALLBACK: string = COPY.UNAVAILABLE;

export function refusal(error: unknown): Refusal {
  if (typeof error === "object" && error !== null && "code" in error && typeof error.code === "string") {
    const fields =
      "fields" in error && Array.isArray(error.fields)
        ? error.fields.filter((field): field is string => typeof field === "string")
        : [];
    return { code: error.code, fields };
  }
  return { code: "UNAVAILABLE", fields: [] };
}

/**
 * The sentence for a refusal. A form names its own fields first, so a body fault reads as
 * "The deadline is 120 to 3600 seconds, or off." rather than the generic line.
 */
export function copyFor(error: unknown, fields: Record<string, string> = {}): string {
  const { code, fields: faults } = refusal(error);
  for (const fault of faults) {
    const own = fields[fault];
    if (own !== undefined) return own;
  }
  return (COPY as Record<string, string>)[code] ?? FALLBACK;
}
