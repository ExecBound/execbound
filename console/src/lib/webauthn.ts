// SPDX-License-Identifier: AGPL-3.0-only
// A passkey for the step-up (#678): the server's request options decoded for
// `navigator.credentials.get`, and the assertion encoded back, exactly as the account security
// page's own script does it. Nothing here is stored; the challenge is single use on the server.

/** The request options as the server serialises them: base64url where WebAuthn wants bytes. */
export interface PasskeyRequestOptions {
  challenge: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
  [field: string]: unknown;
}

/** An assertion as the step-up route takes it. */
export interface PasskeyAssertionBody {
  id: string;
  rawId: string;
  type: "public-key";
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}

function decode(value: string): Uint8Array<ArrayBuffer> {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4));
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);
  return bytes;
}

function encode(value: ArrayBuffer): string {
  let text = "";
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether this browser can ask for a passkey at all. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined";
}

/** Usable options: a challenge and at least one saved passkey to allow. */
export function usableOptions(options: unknown): options is PasskeyRequestOptions {
  if (typeof options !== "object" || options === null) return false;
  const value = options as Partial<PasskeyRequestOptions>;
  return (
    typeof value.challenge === "string" &&
    value.challenge !== "" &&
    Array.isArray(value.allowCredentials) &&
    value.allowCredentials.length > 0
  );
}

/**
 * Ask the browser for an assertion. Called synchronously inside the click: the first await is
 * the browser's own prompt, which Safari requires to be part of the gesture.
 */
export function getAssertion(options: PasskeyRequestOptions): Promise<Credential | null> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...(options as unknown as PublicKeyCredentialRequestOptions),
    challenge: decode(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((item) => ({
      type: "public-key" as const,
      id: decode(item.id),
      ...(item.transports !== undefined ? { transports: item.transports as AuthenticatorTransport[] } : {}),
    })),
  };
  return navigator.credentials.get({ publicKey });
}

/** The assertion the route takes, from what the browser answered. */
export function encodeAssertion(credential: Credential): PasskeyAssertionBody {
  const key = credential as PublicKeyCredential;
  const response = key.response as AuthenticatorAssertionResponse;
  const body: PasskeyAssertionBody = {
    id: key.id,
    rawId: encode(key.rawId),
    type: "public-key",
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
    },
  };
  if (response.userHandle !== null) body.response.userHandle = encode(response.userHandle);
  return body;
}
