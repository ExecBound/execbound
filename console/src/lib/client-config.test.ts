// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it, vi } from "vitest";

import { confirmGeneration, createClientConfig, holdCsrfToken, signInAgain, whileRotating } from "./client-config";
import { FLUSH_DRAFTS } from "./kept";
import { refusedChanges, registerStepUp } from "./step-up";
import { holdWorkspace, invalidateWorkspace, resetWorkspace, staleReason, workspaceStale } from "./workspace-context";

afterEach(() => { vi.unstubAllGlobals(); resetWorkspace(); });

it("pins a request to the displayed workspace and rejects a delayed result after switching", async () => {
  holdWorkspace("generation-a");
  let resolve!: (value: Response) => void;
  const transport = vi.fn<(request: Request) => Promise<Response>>()
    .mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
  vi.stubGlobal("fetch", transport);
  const run = createClientConfig({}).fetch;
  if (run === undefined) throw new Error("Missing fetch");
  const pending = run(new Request("http://localhost/api/console/v1/session"));
  const rejection = expect(pending).rejects.toThrow("Workspace changed");
  expect(transport.mock.calls[0]?.[0].headers.get("X-ExecBound-Workspace")).toBe("generation-a");
  invalidateWorkspace();
  resolve(new Response("{}", { headers: { "X-ExecBound-Workspace": "generation-a" } }));
  await rejection;
});

describe("confirming which session the browser holds", () => {
  const G1 = "11111111-0000-4000-8000-000000000001";
  const G2 = "22222222-0000-4000-8000-000000000002";

  it.each([409, 200])("reads the server's session from the header of a %s and nothing else", async (status) => {
    holdWorkspace(G1);
    const cancel = vi.fn(() => Promise.resolve());
    const transport = vi.fn(() => Promise.resolve({
      status,
      headers: new Headers({ "X-ExecBound-Workspace": G2 }),
      body: { cancel },
      json: () => Promise.reject(new Error("the body is never read")),
    }));
    vi.stubGlobal("fetch", transport);
    expect(await confirmGeneration()).toBe(G2);
    expect(cancel).toHaveBeenCalled();
    const [path, init] = transport.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/api/console/v1/session");
    expect(new Headers(init.headers).get("X-ExecBound-Workspace")).toBe(G1);
    // It installs no token and leaves the tab as it was.
    expect(workspaceStale()).toBe(false);
  });

  it("answers nothing when the read fails", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("offline"))));
    expect(await confirmGeneration()).toBeNull();
  });

  it("is sent by a stale tab too, which every other request is refused", async () => {
    holdWorkspace(G1);
    invalidateWorkspace();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(null, { status: 409, headers: { "X-ExecBound-Workspace": G2 } }))));
    expect(await confirmGeneration()).toBe(G2);
  });

  it("goes stale with nothing known when an answer names another session", async () => {
    holdWorkspace(G1, { id: "aaaaaaaa-0000-4000-8000-00000000000a", name: "Personal" });
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("{}", { headers: { "X-ExecBound-Workspace": G2 } }))));
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    await expect(run(new Request("http://localhost/api/console/v1/session"))).rejects.toThrow("Workspace changed");
    expect(staleReason()).toEqual({ kind: "unknown", from: { id: "aaaaaaaa-0000-4000-8000-00000000000a", name: "Personal" } });
  });
});

it("refuses to adopt a new workspace beneath existing controls", () => {
  holdWorkspace("generation-a");
  holdWorkspace("generation-b");
  expect(workspaceStale()).toBe(true);
});

describe("signing in again (#678)", () => {
  const ID = "abcdef01-0000-4000-8000-000000000001";
  const flush = vi.fn();

  function at(pathname: string, search = "") {
    const assign = vi.fn(() => {
      // The draft store is told to write what it holds before the page is left.
      expect(flush).toHaveBeenCalledTimes(1);
    });
    const dispatchEvent = vi.fn((event: Event) => {
      if (event.type === FLUSH_DRAFTS) flush();
      return true;
    });
    flush.mockClear();
    vi.stubGlobal("window", { location: { pathname, search, assign }, dispatchEvent });
    return assign;
  }

  async function refused(code: string) {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(`{"code":"${code}"}`, { status: 401 })));
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    await run(new Request("http://localhost/api/console/v1/session"));
  }

  it("sends the whole address, page and query, through sign-in on a 401", async () => {
    const assign = at("/activity", `?open=${ID}&state=DENIED`);
    await refused("SESSION_REQUIRED");
    expect(assign).toHaveBeenCalledWith(`/login?review=${encodeURIComponent(`/activity?open=${ID}&state=DENIED`)}`);
  });

  it("reloads any page for the second step, so the server signs the hint first", async () => {
    const assign = at(`/agents/${ID}`);
    await refused("MFA_REQUIRED");
    expect(assign).toHaveBeenCalledWith(`/agents/${ID}`);
    const query = at("/activity", "?state=DENIED");
    await refused("MFA_REQUIRED");
    expect(query).toHaveBeenCalledWith("/activity?state=DENIED");
  });

  it.each(["", "/classic"])("keeps a workspace's approval%s through sign-in", (suffix) => {
    const pathname = `/workspaces/abcdef01-0000-4000-8000-000000000002/approvals/${ID}${suffix}`;
    const assign = at(pathname);
    signInAgain();
    expect(assign).toHaveBeenCalledWith(`/login?review=${encodeURIComponent(pathname)}`);
  });

  it("checks nothing itself: the server keeps only what it can use", () => {
    const assign = at("//other.example");
    signInAgain();
    expect(assign).toHaveBeenCalledWith(`/login?review=${encodeURIComponent("//other.example")}`);
  });

  it.each([
    ["/", ""],
    ["/activity", `?state=${"x".repeat(600)}`],
  ])("uses plain sign-in for %s and an address too long to send", (pathname, search) => {
    const assign = at(pathname, search);
    signInAgain();
    expect(assign).toHaveBeenCalledWith("/login");
  });
});

describe("a change refused for a factor verified too long ago", () => {
  const ADDRESS = "http://localhost/api/console/v1/teammate-invitations";
  const refused = () => new Response('{"code":"MFA_REQUIRED"}', { status: 401 });
  const done = () => new Response('{"invitation_id":"x"}', { status: 200 });
  let withdraw: () => void = () => undefined;

  afterEach(() => {
    withdraw();
    holdCsrfToken("");
  });

  function change(): Promise<Response> {
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    return run(new Request(ADDRESS, { method: "POST", body: '{"email":"new@example.org"}', headers: { "Content-Type": "application/json" } }));
  }

  it("asks in place, then sends the same change again once with the new token", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign }, dispatchEvent: () => true });
    holdCsrfToken("first-token");
    const transport = vi.fn<(request: Request) => Promise<Response>>()
      .mockResolvedValueOnce(refused())
      .mockResolvedValueOnce(done());
    vi.stubGlobal("fetch", transport);
    const prompt = vi.fn(() => {
      holdCsrfToken("rotated-token");
      return Promise.resolve(true);
    });
    withdraw = registerStepUp(prompt);
    const answer = await change();
    expect(answer.status).toBe(200);
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(transport).toHaveBeenCalledTimes(2);
    const [first, second] = transport.mock.calls.map(([request]) => request);
    expect(first?.headers.get("X-CSRF-Token")).toBe("first-token");
    expect(second?.headers.get("X-CSRF-Token")).toBe("rotated-token");
    expect(second?.url).toBe(ADDRESS);
    expect(await second?.text()).toBe('{"email":"new@example.org"}');
    expect(assign).not.toHaveBeenCalled();
  });

  it("leaves the change undone and the page where it was when the person cancels", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign }, dispatchEvent: () => true });
    const transport = vi.fn<(request: Request) => Promise<Response>>().mockResolvedValue(refused());
    vi.stubGlobal("fetch", transport);
    withdraw = registerStepUp(() => Promise.resolve(false));
    const answer = await change();
    expect(answer.status).toBe(401);
    expect(await answer.json()).toEqual({ code: "MFA_REQUIRED" });
    expect(transport).toHaveBeenCalledTimes(1);
    expect(assign).not.toHaveBeenCalled();
  });

  it("answers a second MFA_REQUIRED as it is, without asking again or looping", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign }, dispatchEvent: () => true });
    const transport = vi.fn<(request: Request) => Promise<Response>>().mockImplementation(() => Promise.resolve(refused()));
    vi.stubGlobal("fetch", transport);
    const prompt = vi.fn(() => Promise.resolve(true));
    withdraw = registerStepUp(prompt);
    const answer = await change();
    expect(answer.status).toBe(401);
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(transport).toHaveBeenCalledTimes(2);
    expect(assign).not.toHaveBeenCalled();
  });

  it("asks once for two changes refused together, and sends both again", async () => {
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign: vi.fn() } });
    const transport = vi.fn<(request: Request) => Promise<Response>>()
      .mockResolvedValueOnce(refused())
      .mockResolvedValueOnce(refused())
      .mockResolvedValue(done());
    vi.stubGlobal("fetch", transport);
    let answer: (verified: boolean) => void = () => undefined;
    const prompt = vi.fn(() => new Promise<boolean>((resolve) => { answer = resolve; }));
    withdraw = registerStepUp(prompt);
    const both = Promise.all([change(), change()]);
    await vi.waitFor(() => { expect(prompt).toHaveBeenCalledTimes(1); });
    await vi.waitFor(() => { expect(transport).toHaveBeenCalledTimes(2); });
    answer(true);
    const answers = await both;
    expect(answers.map((item) => item.status)).toEqual([200, 200]);
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(transport).toHaveBeenCalledTimes(4);
  });

  it("tells the question which changes were refused, by method and path (SU11)", async () => {
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign: vi.fn() } });
    const transport = vi.fn<(request: Request) => Promise<Response>>()
      .mockResolvedValueOnce(refused())
      .mockResolvedValueOnce(refused())
      .mockResolvedValue(done());
    vi.stubGlobal("fetch", transport);
    let answer: (verified: boolean) => void = () => undefined;
    const prompt = vi.fn(() => new Promise<boolean>((resolve) => { answer = resolve; }));
    withdraw = registerStepUp(prompt);
    const both = Promise.all([change(), change()]);
    await vi.waitFor(() => { expect(refusedChanges()).toHaveLength(2); });
    expect(refusedChanges()).toEqual([
      { method: "POST", path: "/api/console/v1/teammate-invitations" },
      { method: "POST", path: "/api/console/v1/teammate-invitations" },
    ]);
    expect(prompt).toHaveBeenCalledTimes(1);
    answer(true);
    await both;
    // The question settled, so nothing is left for the next one.
    expect(refusedChanges()).toEqual([]);
  });

  it("still sends a read that needs a factor to the second step of signing in", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign }, dispatchEvent: () => true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(refused()));
    const prompt = vi.fn(() => Promise.resolve(true));
    withdraw = registerStepUp(prompt);
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    await run(new Request("http://localhost/api/console/v1/session"));
    expect(prompt).not.toHaveBeenCalled();
    // The page is opened again, and the server answers it with the second step (#678).
    expect(assign).toHaveBeenCalledWith("/people");
  });

  it("goes to the second step through the page when nothing on the page can ask", async () => {
    const assign = vi.fn();
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign }, dispatchEvent: () => true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(refused()));
    await change();
    expect(assign).toHaveBeenCalledWith("/people");
  });

  it("holds new requests while a code is checked, and checks it after those already sent", async () => {
    vi.stubGlobal("window", { location: { pathname: "/people", search: "", assign: vi.fn() } });
    const order: string[] = [];
    let finishPoll: (value: Response) => void = () => undefined;
    const transport = vi.fn<(request: Request) => Promise<Response>>().mockImplementation((request) => {
      const path = new URL(request.url).pathname;
      order.push(`sent ${path}`);
      if (path === "/api/console/v1/overview") {
        return new Promise<Response>((resolve) => { finishPoll = resolve; });
      }
      return Promise.resolve(new Response('{"csrf_token":"rotated"}', { status: 200 }));
    });
    vi.stubGlobal("fetch", transport);
    const run = createClientConfig({}).fetch;
    if (run === undefined) throw new Error("Missing fetch");
    const poll = run(new Request("http://localhost/api/console/v1/overview"));
    const verification = whileRotating(async (send) => {
      order.push("verifying");
      await send(new Request("http://localhost/api/console/v1/session/verify", { method: "POST", body: "{}" }));
      order.push("verified");
    });
    const later = run(new Request("http://localhost/api/console/v1/session"));
    await Promise.resolve();
    expect(order).toEqual(["sent /api/console/v1/overview"]);
    finishPoll(new Response("{}", { status: 200 }));
    await verification;
    await Promise.all([poll, later]);
    expect(order).toEqual([
      "sent /api/console/v1/overview",
      "verifying",
      "sent /api/console/v1/session/verify",
      "verified",
      "sent /api/console/v1/session",
    ]);
  });
});
