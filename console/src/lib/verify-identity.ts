// SPDX-License-Identifier: AGPL-3.0-only
// Sending the code the step-up dialog asked for (decided 28 September 2026).
//
// `POST /api/console/v1/session/verify` checks it with the same verification the account
// security page uses and replaces the session's cookie and CSRF token as that page does; the
// answer carries the new CSRF token, held in memory like the one the session route hands over,
// so the change sent again carries it. Nothing else is on the wire while it is answered
// (`whileRotating`).

import {
  beginPasskeyStepUp,
  verifyIdentity as verifyRoute,
  verifyIdentityWithPasskey,
} from "../api/sdk.gen";
import { holdCsrfToken, leaveFor, whileRotating } from "./client-config";
import type { PasskeyAssertionBody } from "./webauthn";

/** `verified`: the new token is held. `refused`: that code could not be used; ask again.
 * `unavailable`: nothing was checked, or the session cannot be stepped up here. */
export type Verification = "verified" | "refused" | "unavailable";

function codeOf(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  const code: unknown = error.code;
  return typeof code === "string" ? code : undefined;
}

export async function verifyIdentity(code: string): Promise<Verification> {
  try {
    return await whileRotating(async (fetch) => {
      const { data, error, response } = await verifyRoute({ body: { code }, fetch, throwOnError: false });
      if (data !== undefined) {
        holdCsrfToken(data.csrf_token);
        return "verified";
      }
      const refusal = codeOf(error);
      if (response?.status === 401) {
        // The session ended, or it is still at the second step of signing in, which has a page
        // of its own: neither can be stepped up over this page.
        leaveFor(refusal);
        return "unavailable";
      }
      return refusal === "INVALID_FACTOR" ? "refused" : "unavailable";
    });
  } catch {
    return "unavailable";
  }
}

/** Fresh passkey options for this session's step-up: an ordinary request, since nothing
 * rotates until an assertion is accepted. Null when the account has no passkey or the options
 * could not be fetched. Each finish attempt spends the challenge, so options are used once. */
export async function beginPasskey(): Promise<unknown> {
  try {
    const { data } = await beginPasskeyStepUp({ body: {}, throwOnError: false });
    return data?.options ?? null;
  } catch {
    return null;
  }
}

/** Send an assertion, as `verifyIdentity` sends a code: nothing else is on the wire meanwhile. */
export async function verifyWithPasskey(credential: PasskeyAssertionBody): Promise<Verification> {
  try {
    return await whileRotating(async (fetch) => {
      const { data, error, response } = await verifyIdentityWithPasskey({
        body: { credential },
        fetch,
        throwOnError: false,
      });
      if (data !== undefined) {
        holdCsrfToken(data.csrf_token);
        return "verified";
      }
      const refusal = codeOf(error);
      if (response?.status === 401) {
        leaveFor(refusal);
        return "unavailable";
      }
      return refusal === "INVALID_FACTOR" ? "refused" : "unavailable";
    });
  } catch {
    return "unavailable";
  }
}
