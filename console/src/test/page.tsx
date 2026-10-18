// SPDX-License-Identifier: AGPL-3.0-only
// A page under test: a Query client that never retries, a memory router so a Link renders, the
// toast region, and
// a fetch that answers from a table of routes, recording every request it saw. The generated
// client goes through `client-config`, so a POST carries the token that was held and the
// request is exactly what the gateway would receive.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { expect, vi } from "vitest";

import { client } from "../api/client.gen";
import { Toaster } from "../components/ui/Toast";
import { holdCsrfToken } from "../lib/client-config";
import { PLACEHOLDER, SessionContext, type SessionSummary } from "../lib/session";

export interface Seen {
  method: string;
  path: string;
  headers: Headers;
  body: unknown;
}

export interface Reply {
  status?: number;
  body: unknown;
}

/** A reply, or a function of the request to one; a promised reply holds the response until it settles. */
export type Answer = Reply | ((seen: Seen) => Reply | Promise<Reply>);

/** The answer of a gateway that cannot serve the read just now. */
export const UNAVAILABLE: Reply = { status: 503, body: { code: "UNAVAILABLE", detail: "Unavailable." } };

/** A reply held until the test sends it, for what a page shows while its read is out. */
export function heldReply(): { reply: Promise<Reply>; send: (reply: Reply) => void } {
  let send: (reply: Reply) => void = () => undefined;
  const reply = new Promise<Reply>((resolve) => {
    send = resolve;
  });
  return { reply, send };
}

/** Lets the query client tell its observers what changed, and React render it. */
export async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
}

/** Answers by `"METHOD /path"`; a request with no answer is a 404 refusal. */
export function answerWith(routes: Record<string, Answer>): Seen[] {
  const seen: Seen[] = [];
  holdCsrfToken("token-under-test");
  // Node's Request needs an absolute URL where a browser resolves "/" against the document.
  client.setConfig({ baseUrl: "http://console.test" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string) => {
      const request = input instanceof Request ? input : new Request(input);
      const path = new URL(request.url).pathname;
      const text = request.method === "GET" ? "" : await request.text();
      const record: Seen = {
        method: request.method,
        path,
        headers: request.headers,
        body: text === "" ? undefined : (JSON.parse(text) as unknown),
      };
      seen.push(record);
      const answer = routes[`${request.method} ${path}`];
      const resolved = await (
        answer === undefined
          ? { status: 404, body: { code: "NOT_FOUND", detail: "There is nothing here." } }
          : typeof answer === "function"
            ? answer(record)
            : answer
      );
      return new Response(JSON.stringify(resolved.body), {
        status: resolved.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  return seen;
}

export function renderPage(ui: ReactNode, session: SessionSummary = PLACEHOLDER) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 0 }, mutations: { retry: 0 } } });
  const rootRoute = createRootRoute({
    component: () => (
      <SessionContext.Provider value={session}>
        <QueryClientProvider client={queryClient}>
          {ui}
          <Toaster />
        </QueryClientProvider>
      </SessionContext.Provider>
    ),
  });
  const router = createRouter({
    routeTree: rootRoute,
    history: createMemoryHistory({ initialEntries: ["/"] }),
  });
  // The client comes back with the render so a test can say what the caches hold afterwards.
  return Object.assign(render(<RouterProvider router={router} />), { queryClient });
}

/** A pasted secret is kept nowhere a page could give it away from: no query or mutation record,
 * no browser storage, and nowhere in the document. */
export async function keptNowhere(queryClient: QueryClient, secret: string) {
  await waitFor(() => {
    const kept = JSON.stringify([
      queryClient.getMutationCache().getAll().map((mutation) => mutation.state),
      queryClient.getQueryCache().getAll().map((query) => query.state.data),
    ]);
    expect(kept).not.toContain(secret);
  });
  for (const storage of [window.localStorage, window.sessionStorage]) {
    for (let index = 0; index < storage.length; index += 1) {
      const name = storage.key(index) ?? "";
      expect(`${name}=${storage.getItem(name) ?? ""}`).not.toContain(secret);
    }
  }
  expect(document.documentElement.innerHTML).not.toContain(secret);
}
