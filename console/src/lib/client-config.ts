// SPDX-License-Identifier: AGPL-3.0-only
// The generated client's runtime configuration (#333). Same origin, the session
// cookie and nothing else for authority; every mutation carries the CSRF token the session
// route handed over, held in memory here and nowhere else; every response's release header is
// compared with the built one; a 401 sends the person to sign in.
//
// One 401 is answered in place (decided 28 September 2026): a change refused MFA_REQUIRED
// because the session's factor was verified too long ago asks for a code over the page
// (`step-up.ts`), and once one is accepted the change is sent again, exactly once, with the
// session's new CSRF token. Anything else that needs a factor still goes to `/mfa`.

import type { CreateClientConfig } from "../api/client.gen";
import { noteServerTime } from "./clock";
import { noteRelease } from "./release";
import { canStepUp, stepUp } from "./step-up";
import { installConfirm, invalidateWorkspace, workspaceGeneration, workspaceStale } from "./workspace-context";

let csrfToken = "";
// What the draft store listens for before the page is left (`lib/kept.ts`'s `FLUSH_DRAFTS`),
// named here rather than imported so a cold approval link loads neither module.
const FLUSH_DRAFTS = "eb:flush-drafts";
// The longest address worth sending through sign-in; the server keeps at most 256 characters of
// what it accepts, and refuses anything past this before it reads it.
const RETURN_MAX = 512;
// How long a verification waits for requests already on the wire before it goes anyway.
const QUIET_LIMIT_MS = 5000;

/** Remember the session's token; the session route and a verification are where it comes from. */
export function holdCsrfToken(token: string): void {
  csrfToken = token;
}

export function forgetCsrfToken(): void {
  csrfToken = "";
}

/**
 * Sign in again and come back here (#678): the page and its query ride to sign-in as the
 * `review` hint, which the server keeps only in its own closed grammar of console pages, so
 * nothing is checked here and the two can never disagree. What was typed into a keeping field is
 * written first.
 */
export function signInAgain(): void {
  window.dispatchEvent(new Event(FLUSH_DRAFTS));
  const place = window.location.pathname + window.location.search;
  window.location.assign(place === "/" || place.length > RETURN_MAX ? "/login" : `/login?review=${encodeURIComponent(place)}`);
}

/** Where a 401 sends the person: the second step of signing in, or sign-in itself. */
export function leaveFor(code: string | undefined): void {
  if (code === "MFA_REQUIRED") {
    // Re-enter through the page, so the server signs the return hint before it answers `/mfa`.
    window.dispatchEvent(new Event(FLUSH_DRAFTS));
    window.location.assign(window.location.pathname + window.location.search);
  } else signInAgain();
}

// A verification replaces the session's cookies, so while one is answered nothing else may be
// on the wire: a request sent with the old cookie and answered after the rotation would read as
// a session that ended, and a renewal answered after it would write the old cookie back.
// `rotating` holds new requests until the verification is answered; `quiet()` waits for the
// ones already sent.
let rotating: Promise<void> | null = null;
let inFlight = 0;
let idle: (() => void)[] = [];

function quiet(): Promise<void> {
  if (inFlight === 0) return Promise.resolve();
  return new Promise<void>((resolve) => {
    idle.push(resolve);
    setTimeout(resolve, QUIET_LIMIT_MS);
  });
}

function settled(): void {
  inFlight -= 1;
  if (inFlight > 0) return;
  const waiting = idle;
  idle = [];
  for (const resolve of waiting) resolve();
}

/** One request, as it leaves: the workspace it was rendered for, the CSRF token on a change,
 * and the checks every answer gets. */
async function exchange(request: Request): Promise<Response> {
  if (workspaceStale()) throw new Error("Workspace changed");
  const generation = workspaceGeneration();
  if (generation !== "") request.headers.set("X-ExecBound-Workspace", generation);
  if (request.method !== "GET" && request.method !== "HEAD") {
    request.headers.set("X-CSRF-Token", csrfToken);
  }
  inFlight += 1;
  let response: Response;
  try {
    response = await fetch(request);
  } finally {
    settled();
  }
  const received = response.headers.get("X-ExecBound-Workspace");
  if (workspaceStale() || (generation !== "" && received !== null && received !== generation)) {
    invalidateWorkspace(received);
    throw new Error("Workspace changed");
  }
  noteRelease(response.headers);
  noteServerTime(response.headers);
  return response;
}

/**
 * Which session this browser's cookie selects now, as the server says in its answer's header:
 * the one read another tab's announcement waits for (#678). It is sent outside `exchange()`, so a
 * stale tab may send it, and it acts on nothing: the body, a CSRF token included, is never read.
 */
export async function confirmGeneration(): Promise<string | null> {
  try {
    const response = await fetch("/api/console/v1/session", {
      credentials: "same-origin",
      headers: { "X-ExecBound-Workspace": workspaceGeneration() },
    });
    void response.body?.cancel();
    return response.headers.get("X-ExecBound-Workspace");
  } catch {
    return null;
  }
}
installConfirm(confirmGeneration);

async function send(request: Request): Promise<Response> {
  while (rotating !== null) await rotating;
  return exchange(request);
}

/**
 * Run a verification with nothing else on the wire, handing it the one way to send that is not
 * held back. Later requests wait for it; it waits for earlier ones, up to five seconds.
 */
export async function whileRotating<T>(work: (fetch: typeof globalThis.fetch) => Promise<T>): Promise<T> {
  while (rotating !== null) await rotating;
  let release: () => void = () => undefined;
  rotating = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    await quiet();
    return await work((input, init) => exchange(new Request(input, init)));
  } finally {
    rotating = null;
    release();
  }
}

async function refusalCode(response: Response): Promise<string | undefined> {
  const failure = (await response.clone().json().catch(() => null)) as { code?: unknown } | null;
  return typeof failure?.code === "string" ? failure.code : undefined;
}

export const createClientConfig: CreateClientConfig = (config) => ({
  ...config,
  baseUrl: "/",
  credentials: "same-origin",
  throwOnError: true,
  fetch: async (input, init) => {
    const request = new Request(input, init);
    // A body is read once, so a change keeps a copy to be sent again after a step-up.
    const change = request.method !== "GET" && request.method !== "HEAD";
    const spare = change ? request.clone() : null;
    const response = await send(request);
    if (response.status !== 401) return response;
    const code = await refusalCode(response);
    if (code === "MFA_REQUIRED" && spare !== null && canStepUp()) {
      // Cancelled: the refusal stands, the page says the change was not made, nothing moves.
      if (!(await stepUp({ method: spare.method, path: new URL(spare.url).pathname }))) return response;
      // Sent again once. A second MFA_REQUIRED is answered as it is, never with a second code.
      const again = await send(spare);
      if (again.status === 401 && (await refusalCode(again)) !== "MFA_REQUIRED") signInAgain();
      return again;
    }
    leaveFor(code);
    return response;
  },
});
