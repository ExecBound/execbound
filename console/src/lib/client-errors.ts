// SPDX-License-Identifier: AGPL-3.0-only
// A page that fails reports itself to the server once (#678), so an operator learns that a
// release broke a page without anybody describing it. The report is the route's pattern (never
// the path a person is on, which carries identifiers), the build's release, the error's reduced
// name and a SHA-256 of the component stack: never a message, a query string or page data. The
// server's model refuses any other field. Each error is reported at most once and a page load
// reports at most three; a failure to report is ignored. Where `crypto.subtle` is missing (a
// console served over plain HTTP) nothing is sent and no reference is shown.
//
// The reference people can quote is the first eight characters of the hash. It names the failure,
// not an incident: the same failure in the same build gives the same reference everywhere,
// because nothing about the session is hashed.

import { reportClientErrorMutation } from "../api/@tanstack/react-query.gen";
import { codeOf } from "./errors";

/** The four fields the server's model takes, and nothing else. */
export interface ClientErrorReport {
  route: string;
  release: string;
  name: string;
  stack_hash: string;
}

const ROUTE = /^\/[A-Za-z0-9/_.$-]*$/;
const RELEASE = /^[0-9a-f]{0,40}$/;
/** Reports a page load may make. */
export const REPORT_LIMIT = 3;

/** Each error reported, with the reference its report gave, so a page drawn again shows it again. */
const reported = new WeakMap<object, string>();
let sent = 0;

export interface ReportInput {
  error: unknown;
  /** The erroring match's route id, such as `/agents_/$agentId`; the root's is `__root__`. */
  routeId: string | undefined;
  componentStack?: string;
  release: string;
}

/** The route id as the server takes it, or nothing where it would be refused. */
export function reportRoute(routeId: string | undefined): string | undefined {
  if (routeId === undefined) return undefined;
  const route = routeId === "__root__" ? "/" : routeId;
  return route.length <= 200 && ROUTE.test(route) ? route : undefined;
}

/** The error's name, reduced to what the server takes. */
export function reportName(error: unknown): string {
  const raw = error instanceof Error ? error.name : "";
  const name = raw.replace(/[^A-Za-z0-9_.:\- ]/g, "").slice(0, 80).trim();
  return name === "" ? "Error" : name;
}

async function sha256(text: string): Promise<string | undefined> {
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (subtle === undefined) return undefined;
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The report's body, or nothing where this error is not one to report or cannot be hashed. */
export async function reportFor({ error, routeId, componentStack, release }: ReportInput): Promise<ClientErrorReport | undefined> {
  if (codeOf(error) !== undefined) return undefined;
  const route = reportRoute(routeId);
  if (route === undefined) return undefined;
  const name = reportName(error);
  const stack = componentStack !== undefined && componentStack.trim() !== "" ? componentStack : `${name}\n${route}`;
  const hash = await sha256(stack);
  if (hash === undefined) return undefined;
  return { route, release: RELEASE.test(release) ? release : "", name, stack_hash: hash };
}

/**
 * Reports the error once and answers the reference to show, or nothing: for a typed refusal, a
 * page load past its three reports, a route the server would refuse, or a browser without
 * `crypto.subtle`. An error already reported is not sent again, and answers its reference again.
 * A failed send is swallowed; the reference is still the hash's.
 */
export async function send(input: ReportInput): Promise<string | undefined> {
  const { error } = input;
  if (typeof error === "object" && error !== null && reported.has(error)) return reported.get(error);
  if (sent >= REPORT_LIMIT) return undefined;
  let body: ClientErrorReport | undefined;
  try {
    body = await reportFor(input);
  } catch {
    return undefined;
  }
  if (body === undefined) return undefined;
  const reference = body.stack_hash.slice(0, 8);
  if (typeof error === "object" && error !== null) reported.set(error, reference);
  sent += 1;
  try {
    // The server reads this body through its mutation guard and its own model, which the
    // generated document does not describe, so the generated options take no body type. The
    // generated mutation is used rather than the plain call so the report reaches the client the
    // shell already loaded, without splitting the generated calls into a chunk of their own.
    await reportClientErrorMutation().mutationFn?.({ body: body as never }, undefined as never);
  } catch {
    // Reporting is best effort; the page has already said what it can.
  }
  return reference;
}

/** Forgets what this page load reported, between tests. */
export function forgetReports(): void {
  sent = 0;
}
