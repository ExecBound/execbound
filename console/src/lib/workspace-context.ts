// SPDX-License-Identifier: AGPL-3.0-only
// Kept only in memory: a tab stays bound to the workspace it rendered until a full reload. Tabs
// tell one another over one channel when a switch or a new sign-in moves the browser, so a tab
// left behind can say what happened. A message is a hint that grants nothing: it is checked for
// shape before anything is read from it, an announced sign-in is confirmed with the server
// before a tab acts on it, and the server's generation check stays the authority (#678).

export interface WorkspaceRef {
  readonly id: string;
  readonly name: string;
}
export type StaleReason =
  | { kind: "elsewhere"; from: WorkspaceRef | null; to: WorkspaceRef }
  | { kind: "same"; from: WorkspaceRef | null }
  | { kind: "unknown"; from: WorkspaceRef | null };
interface Switching {
  v: 1;
  kind: "switching";
  tenant_id: string;
  name: string;
}
interface Entered {
  v: 1;
  kind: "entered";
  generation: string;
  tenant_id: string;
  name: string;
}
export type Message = Switching | Entered;

const CHANNEL = "execbound-workspace";
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

let generation = "";
let held: WorkspaceRef | null = null;
let reason: StaleReason | null = null;
// The most recent valid announcement of a sign-in, and the confirmation read now running.
let latest: Entered | null = null;
let confirming: Promise<string | null> | null = null;
let announced = "";
let confirm: () => Promise<string | null> = () => Promise.resolve(null);
const listeners = new Set<() => void>();

export const workspaceGeneration = () => generation;
export const workspaceStale = () => reason !== null;
export const staleReason = () => reason;
export function subscribeWorkspace(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

function become(next: StaleReason): void {
  reason = next;
  for (const listener of listeners) listener();
}
/** The reason a message naming `ref` gives, from the workspace this tab showed. */
function reasonFrom(ref: WorkspaceRef): StaleReason {
  return held !== null && ref.id === held.id ? { kind: "same", from: held } : { kind: "elsewhere", from: held, to: ref };
}
const refOf = (message: Message): WorkspaceRef => ({ id: message.tenant_id, name: message.name });

/**
 * The tab goes stale. Given the generation a response's header reported, the reason comes from
 * the latest announced sign-in when that is the one the server named, else nothing is known.
 */
export function invalidateWorkspace(reported?: string | null): void {
  if (reason !== null) return;
  become(latest !== null && reported === latest.generation ? reasonFrom(refOf(latest)) : { kind: "unknown", from: held });
}

/** The session this tab renders. A view for another session makes the tab stale, named by it. */
export function holdWorkspace(value: string, workspace?: WorkspaceRef): void {
  if (generation !== "" && value !== generation) {
    if (reason === null) become(workspace === undefined ? { kind: "unknown", from: held } : reasonFrom(workspace));
  } else if (reason === null) {
    generation = value;
    if (workspace !== undefined) held = workspace;
  }
}

export function resetWorkspace(): void {
  generation = "";
  held = null;
  reason = null;
  latest = null;
  confirming = null;
  announced = "";
}

/** How a confirmation read is sent; the client's configuration supplies it. */
export function installConfirm(read: () => Promise<string | null>): void {
  confirm = read;
}

function post(...messages: unknown[]): void {
  if (typeof BroadcastChannel === "undefined") return;
  const channel = new BroadcastChannel(CHANNEL);
  for (const message of messages) channel.postMessage(message);
  channel.close();
}

/**
 * This tab has switched the browser to `to`: it stops here, and tells the others where the
 * browser went, then sends the bare word an earlier release understands.
 */
export function announceSwitch(to: WorkspaceRef): void {
  if (reason === null) become(reasonFrom(to));
  post({ v: 1, kind: "switching", tenant_id: to.id, name: to.name } satisfies Switching, "changed");
}

/** Once per session, a tab that holds it announces it, so a tab left on an earlier one can say so. */
export function announceEntered(value: string, workspace: WorkspaceRef): void {
  if (reason !== null || value === announced) return;
  announced = value;
  post({ v: 1, kind: "entered", generation: value, tenant_id: workspace.id, name: workspace.name } satisfies Entered);
}

/** A message as this tab will read it, or null for anything not exactly one of its shapes. */
export function readMessage(data: unknown): Message | "legacy" | null {
  if (data === "changed") return "legacy";
  if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
  const value = data as Record<string, unknown>;
  const { v, kind, tenant_id: tenant, name, generation: entered } = value;
  if (v !== 1 || typeof tenant !== "string" || !UUID.test(tenant) || typeof name !== "string") return null;
  // Counted in code points, as the server bounds a workspace's name, never in UTF-16 units.
  const length = Array.from(name).length;
  if (length < 1 || length > 200) return null;
  const keys = Object.keys(value).length;
  if (kind === "switching" && keys === 4) return { v, kind, tenant_id: tenant, name };
  if (kind === "entered" && keys === 5 && typeof entered === "string" && UUID.test(entered)) {
    return { v, kind, generation: entered, tenant_id: tenant, name };
  }
  return null;
}

/** One confirmation read at a time; a second announcement waits for the answer to the first. */
function confirmed(): Promise<string | null> {
  confirming ??= confirm().finally(() => { confirming = null; });
  return confirming;
}

/** Read one message from another tab; the latest valid message names the reason. */
export async function receive(data: unknown): Promise<void> {
  const message = readMessage(data);
  if (message === null) return;
  if (message === "legacy") {
    if (reason === null) become({ kind: "unknown", from: held });
    return;
  }
  if (message.kind === "switching") {
    become(reasonFrom(refOf(message)));
    return;
  }
  if (generation === "" || message.generation === generation) return;
  latest = message;
  const answer = await confirmed();
  // No answer changes nothing; the held generation means the announcement was out of date.
  if (answer === null || answer === generation) return;
  if (answer === message.generation) become(reasonFrom(refOf(message)));
  else if (reason === null) become({ kind: "unknown", from: held });
}

export function watchWorkspaceChanges(): () => void {
  if (typeof BroadcastChannel === "undefined") return () => undefined;
  const channel = new BroadcastChannel(CHANNEL);
  channel.onmessage = (event: MessageEvent<unknown>) => { void receive(event.data); };
  return () => { channel.close(); };
}
