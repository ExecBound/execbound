// SPDX-License-Identifier: AGPL-3.0-only
// The console API's refusals are typed codes (#333); the client maps each to
// copy here, so a refusal is never shown as a server string. An error the client throws is
// the parsed refusal body, `{code, detail}`; anything else is a failure to reach the server.

const COPY: Record<string, string> = {
  INVALID_REQUEST: "The request was not understood.",
  INVALID_BODY: "The form was not accepted; check the reason and the record.",
  INVALID_CONTINUATION: "The record changed since it was read. Close it and open it again.",
  SESSION_REQUIRED: "Sign in to continue.",
  // Only a change whose step-up was cancelled, or refused again once resent, reads this.
  MFA_REQUIRED: "This change was not made. Try again, and enter a code when ExecBound asks you to verify your identity.",
  FORBIDDEN: "This is not yours to do.",
  INVALID_CSRF: "Your session's token did not match; reload the page.",
  INVALID_ORIGIN: "The request came from somewhere else.",
  NOT_FOUND: "There is nothing here.",
  METHOD_NOT_ALLOWED: "This address does not take that method.",
  CONFLICT: "Something changed first; the record may already be settled.",
  WORKSPACE_CHANGED: "The workspace changed. Reload before continuing.",
  DIRECTORY_REQUIRED: "Use this workspace's organization sign-in to continue.",
  TOO_LARGE: "The form is too large.",
  UNSUPPORTED_MEDIA_TYPE: "The request was not sent as JSON.",
  STOPPED: "The tenant is stopped.",
  TOO_MANY_REQUESTS: "Too many requests; try again shortly.",
  UNAVAILABLE: "ExecBound is unavailable; try again shortly.",
};

export function codeOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  const code: unknown = error.code;
  return typeof code === "string" ? code : undefined;
}

export function copyFor(error: unknown): string {
  const code = codeOf(error);
  if (code === undefined) return "ExecBound could not be reached; try again.";
  return COPY[code] ?? "The request was refused.";
}
