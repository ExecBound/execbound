// SPDX-License-Identifier: AGPL-3.0-only
// The console API as fetch sees it in a test, keyed by path (#333). A browser
// resolves the generated client's relative URLs against the page; Node's Request does not,
// so the harness resolves them the same way. Every call is remembered with its body, so a
// test can say what was sent as well as what was shown.

import { vi } from "vitest";

export const ORIGIN = "http://console.test";

export interface Call {
  method: string;
  path: string;
  search: string;
  body: unknown;
}

/** An answer is a JSON body, or a function of the request and its parsed body. */
export type Responder = (request: Request, body: unknown) => Response | Promise<Response>;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export function serve(answers: Record<string, unknown>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "Request",
    class extends Request {
      constructor(input: RequestInfo | URL, init?: RequestInit) {
        super(typeof input === "string" && input.startsWith("/") ? new URL(input, ORIGIN).href : input, init);
      }
    },
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url, ORIGIN);
      const text = request.method === "GET" ? "" : await request.text();
      let body: unknown;
      try {
        body = text === "" ? undefined : JSON.parse(text);
      } catch {
        body = text;
      }
      calls.push({ method: request.method, path: url.pathname, search: url.search, body });
      const answer = answers[url.pathname];
      if (answer === undefined) return json({ code: "NOT_FOUND", detail: "There is nothing here." }, 404);
      if (typeof answer === "function") return (answer as Responder)(request, body);
      return json(answer);
    }),
  );
  return calls;
}

/** Whether one of the calls hit a path with a query starting as given. */
export function called(calls: Call[], method: string, path: string, search = ""): boolean {
  return calls.some((call) => call.method === method && call.path === path && call.search.startsWith(search));
}

/** Whether one of the calls hit a path with exactly these query parameters, in any order. */
export function calledWith(calls: Call[], method: string, path: string, params: Record<string, string>): boolean {
  return calls.some((call) => {
    if (call.method !== method || call.path !== path) return false;
    const found = new URLSearchParams(call.search);
    const keys = new Set([...found.keys()]);
    return (
      keys.size === Object.keys(params).length &&
      Object.entries(params).every(([key, value]) => found.get(key) === value)
    );
  });
}
