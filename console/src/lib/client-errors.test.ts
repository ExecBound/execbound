// SPDX-License-Identifier: AGPL-3.0-only
// A failed page's report (NV16, #678): the route's pattern, a hex release, a reduced name and a
// hash, never a message or a path; once an error, three a page load, none for a typed refusal and
// none where the browser cannot hash.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { client } from "../api/client.gen";
import { forgetReports, reportFor, reportName, reportRoute, send } from "./client-errors";

interface Posted {
  path: string;
  body: Record<string, unknown>;
}

function capture(fail = false): Posted[] {
  const posted: Posted[] = [];
  client.setConfig({ baseUrl: "http://console.test" });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      if (fail) throw new TypeError("Failed to fetch");
      posted.push({ path: new URL(input.url).pathname, body: (await input.json()) as Record<string, unknown> });
      return new Response(null, { status: 204 });
    }),
  );
  return posted;
}

beforeEach(() => {
  forgetReports();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the report's fields (NV16, #678)", () => {
  it("sends the route's pattern as it is and the root as /, and never a route the server refuses", () => {
    expect(reportRoute("/approvals/$approvalId")).toBe("/approvals/$approvalId");
    expect(reportRoute("/agents_/$agentId")).toBe("/agents_/$agentId");
    expect(reportRoute("__root__")).toBe("/");
    expect(reportRoute("/approvals/<script>")).toBeUndefined();
    expect(reportRoute("/x?y=1")).toBeUndefined();
    expect(reportRoute(undefined)).toBeUndefined();
  });

  it("reduces the name to what the server takes", () => {
    const typed = new TypeError("x");
    typed.name = "Type<Error>";
    expect(reportName(typed)).toBe("TypeError");
    expect(reportName({})).toBe("Error");
    expect(reportName("text")).toBe("Error");
  });

  it("carries exactly four fields, a hex release and a 64-character hash, and no message or path", async () => {
    window.history.replaceState(null, "", "/agents/1a2b3c4d-0000-4000-8000-000000000001?section=connection");
    const body = await reportFor({ error: new Error("secret 4111 in /agents/1a2b"), routeId: "/agents_/$agentId", componentStack: "at Agent\nat Shell", release: "dev" });
    expect(body).toBeDefined();
    expect(Object.keys(body ?? {}).sort()).toEqual(["name", "release", "route", "stack_hash"]);
    expect(body?.release).toBe("");
    expect(body?.stack_hash).toMatch(/^[0-9a-f]{64}$/);
    const text = JSON.stringify(body);
    expect(text).not.toContain("secret");
    expect(text).not.toContain("4111");
    expect(text).not.toContain(window.location.pathname);
    expect(text).not.toContain("section=connection");
    const released = await reportFor({ error: new Error("x"), routeId: "/", release: "abc123" });
    expect(released?.release).toBe("abc123");
  });
});

describe("sending (NV16, #678)", () => {
  it("sends one report an error, three a page load, and none for a typed refusal", async () => {
    const posted = capture();
    const once = new Error("a");
    const reference = await send({ error: once, routeId: "/", release: "" });
    expect(reference).toMatch(/^[0-9a-f]{8}$/);
    // The same error again is not sent again; it answers the same reference.
    expect(await send({ error: once, routeId: "/", release: "" })).toBe(reference);
    expect(await send({ error: { code: "FORBIDDEN" }, routeId: "/", release: "" })).toBeUndefined();
    for (const name of ["b", "c", "d"]) await send({ error: new Error(name), routeId: "/", release: "" });
    expect(posted).toHaveLength(3);
    expect(posted.every((report) => report.path === "/api/console/v1/client-errors")).toBe(true);
    expect(posted[0]?.body.stack_hash).toEqual(expect.stringMatching(/^[0-9a-f]{64}$/));
  });

  it("swallows a failed send", async () => {
    capture(true);
    await expect(send({ error: new Error("a"), routeId: "/", release: "" })).resolves.toMatch(/^[0-9a-f]{8}$/);
  });

  it("sends nothing and gives no reference where the browser cannot hash", async () => {
    const posted = capture();
    vi.stubGlobal("crypto", {});
    await expect(send({ error: new Error("a"), routeId: "/", release: "" })).resolves.toBeUndefined();
    expect(posted).toHaveLength(0);
  });
});
