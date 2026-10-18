// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  announceEntered,
  announceSwitch,
  holdWorkspace,
  installConfirm,
  invalidateWorkspace,
  readMessage,
  receive,
  resetWorkspace,
  staleReason,
  workspaceStale,
} from "./workspace-context";

const G1 = "11111111-0000-4000-8000-000000000001";
const G2 = "22222222-0000-4000-8000-000000000002";
const G3 = "33333333-0000-4000-8000-000000000003";
const A = { id: "aaaaaaaa-0000-4000-8000-00000000000a", name: "Personal" };
const B = { id: "bbbbbbbb-0000-4000-8000-00000000000b", name: "Team <script>" };
const C = { id: "cccccccc-0000-4000-8000-00000000000c", name: "Customer C" };

const switching = (to: { id: string; name: string }) => ({ v: 1, kind: "switching", tenant_id: to.id, name: to.name });
const entered = (generation: string, to: { id: string; name: string }) =>
  ({ v: 1, kind: "entered", generation, tenant_id: to.id, name: to.name });

let answer: string | null;
let reads: number;

beforeEach(() => {
  answer = null;
  reads = 0;
  installConfirm(() => { reads += 1; return Promise.resolve(answer); });
  holdWorkspace(G1, A);
});
afterEach(() => { vi.unstubAllGlobals(); resetWorkspace(); });

describe("reading a message", () => {
  it("accepts the two shapes and the bare word an earlier release sends", () => {
    expect(readMessage(switching(B))).toEqual(switching(B));
    expect(readMessage(entered(G2, B))).toEqual(entered(G2, B));
    expect(readMessage("changed")).toBe("legacy");
  });

  it("counts a name in code points: two hundred emoji pass, two hundred and one characters do not", () => {
    const emoji = "\u{1F600}".repeat(200);
    expect(emoji.length).toBe(400);
    expect(readMessage(switching({ id: B.id, name: emoji }))).not.toBeNull();
    expect(readMessage(switching({ id: B.id, name: "x".repeat(201) }))).toBeNull();
  });

  it.each([
    ["a bad tenant id", { ...switching(B), tenant_id: "not-a-uuid" }],
    ["a bad generation", { ...entered(G2, B), generation: "G2" }],
    ["an upper-case id", { ...switching(B), tenant_id: B.id.toUpperCase() }],
    ["an empty name", switching({ id: B.id, name: "" })],
    ["a name that is not text", { ...switching(B), name: 7 }],
    ["another version", { ...switching(B), v: 2 }],
    ["another kind", { ...switching(B), kind: "left" }],
    ["an extra field", { ...switching(B), to: "/agents" }],
    ["a number", 7],
    ["null", null],
    ["an array", [switching(B)]],
    ["another word", "switched"],
  ])("ignores %s", (_, data) => {
    expect(readMessage(data)).toBeNull();
  });
});

describe("receiving a message", () => {
  it("ignores an announcement of the tab's own session", async () => {
    await receive(entered(G1, A));
    expect(workspaceStale()).toBe(false);
    expect(reads).toBe(0);
  });

  it("ignores an announcement before the tab holds a session", async () => {
    resetWorkspace();
    await receive(entered(G2, B));
    expect(workspaceStale()).toBe(false);
    expect(reads).toBe(0);
  });

  it("goes stale at once on a switch, naming where the browser went", async () => {
    await receive(switching(B));
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });

  it("reads a switch back to its own workspace as the same workspace", async () => {
    await receive(switching(A));
    expect(staleReason()).toEqual({ kind: "same", from: A });
  });

  it("goes stale with nothing known on the bare word", async () => {
    await receive("changed");
    expect(staleReason()).toEqual({ kind: "unknown", from: A });
  });

  it("acts on an announced sign-in only once the server names that session", async () => {
    answer = G2;
    await receive(entered(G2, B));
    expect(reads).toBe(1);
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });

  it("stays current when the server still names this tab's session (an announcement out of date)", async () => {
    answer = G1;
    await receive(entered(G2, B));
    expect(workspaceStale()).toBe(false);
  });

  it("goes stale with nothing known when the server names a third session", async () => {
    answer = G3;
    await receive(entered(G2, B));
    expect(staleReason()).toEqual({ kind: "unknown", from: A });
  });

  it("keeps a stale tab's reason when the server names a third session", async () => {
    await receive(switching(B));
    answer = G3;
    await receive(entered(G2, C));
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });

  it("changes nothing when the confirmation read fails", async () => {
    answer = null;
    await receive(entered(G2, B));
    expect(workspaceStale()).toBe(false);
  });

  it("lets the latest message name the reason, whichever way the browser went", async () => {
    await receive(switching(B));
    await receive(switching(A));
    expect(staleReason()).toEqual({ kind: "same", from: A });
    await receive(switching(C));
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: C });
  });

  it("reads a confirmed sign-in again to this tab's workspace as the same workspace", async () => {
    await receive(switching(B));
    answer = G3;
    await receive(entered(G3, A));
    expect(staleReason()).toEqual({ kind: "same", from: A });
  });

  it("stays current when a tab announces a session the browser has already left", async () => {
    // This tab holds G2 in B; another tab's first read, sent before the switch and answered after
    // it, announces the earlier G1 in A. The server still names G2.
    resetWorkspace();
    holdWorkspace(G2, B);
    answer = G2;
    await receive(entered(G1, A));
    expect(workspaceStale()).toBe(false);
  });

  it("sends one confirmation read at a time, and checks a second announcement against its answer", async () => {
    let finish: (value: string | null) => void = () => undefined;
    installConfirm(() => { reads += 1; return new Promise((resolve) => { finish = resolve; }); });
    const first = receive(entered(G2, B));
    const second = receive(entered(G3, C));
    finish(G3);
    await Promise.all([first, second]);
    expect(reads).toBe(1);
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: C });
  });
});

describe("a stale answer and a session view", () => {
  it("names the announced workspace when a response reports its session", async () => {
    answer = null;
    await receive(entered(G2, B));
    invalidateWorkspace(G2);
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });

  it("knows nothing when a response reports any other session", () => {
    invalidateWorkspace(G3);
    expect(staleReason()).toEqual({ kind: "unknown", from: A });
  });

  it("takes the reason from a view answered for another session", () => {
    holdWorkspace(G2, B);
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });
});

describe("announcing", () => {
  it("posts the switch before the bare word, and stops this tab", () => {
    const posted: unknown[] = [];
    vi.stubGlobal("BroadcastChannel", class {
      postMessage(message: unknown) { posted.push(message); }
      close() { /* nothing held */ }
    });
    announceSwitch(B);
    expect(posted).toEqual([switching(B), "changed"]);
    expect(staleReason()).toEqual({ kind: "elsewhere", from: A, to: B });
  });

  it("announces a session once, and never from a stale tab", () => {
    const posted: unknown[] = [];
    vi.stubGlobal("BroadcastChannel", class {
      postMessage(message: unknown) { posted.push(message); }
      close() { /* nothing held */ }
    });
    announceEntered(G1, A);
    announceEntered(G1, A);
    expect(posted).toEqual([entered(G1, A)]);
    invalidateWorkspace();
    announceEntered(G2, B);
    expect(posted).toHaveLength(1);
  });
});
