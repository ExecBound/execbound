// SPDX-License-Identifier: AGPL-3.0-only
// The console's one draft store (#678): text a person typed and has not sent, kept in this tab's
// `sessionStorage` so it survives signing in again. A draft is bound to the person who typed it
// and to the moment its subject stops being useful, never leaves the tab, and is never a
// show-once value, a query cache entry, an address or a log line. A browser that refuses
// storage loses only the convenience: every read and write is guarded.
//
// Two kinds, each as `{ p: <principal id>, x: <expires_at>, t: <text> }`: the comment on an
// approval decision, under `eb:draft:approval:<approval_id>`, which lives as long as the approval;
// and a new policy document, under `eb:draft:policy:new`, which lives thirty minutes from its last
// write, so it crosses from a session that ended into the next sign-in, after the old session's
// hard end included. Only the files the lint allowlist names may import this module.

import { useRef, useState } from "react";

import { serverNow } from "./clock";
import { FLUSH_DRAFTS, noteStorage } from "./kept";

const PREFIX = "eb:draft:";
const APPROVAL = `${PREFIX}approval:`;
const POLICY = `${PREFIX}policy:new`;
/** The decision comment's own bound, which the field enforces too. */
export const DRAFT_LIMIT = 500;
/** A policy document longer than this, in UTF-8 bytes, is not kept. */
export const POLICY_LIMIT = 64 * 1024;
/** How long a kept policy document lives after its last write. */
export const POLICY_LIFE_MS = 30 * 60 * 1000;
/** A document can be large, so its writes wait for typing to pause. */
export const POLICY_DEBOUNCE_MS = 250;

interface Stored {
  p: string;
  x: string;
  t: string;
}

/** Runs one storage step; a refusal or a malformed value is nothing kept. */
function guarded<T>(step: (store: Storage) => T, otherwise: T): T {
  try {
    return step(window.sessionStorage);
  } catch {
    return otherwise;
  }
}

function read(key: string): Stored | null {
  return guarded((store) => {
    const value = JSON.parse(store.getItem(key) ?? "null") as Partial<Stored> | null;
    return typeof value?.p === "string" && typeof value.x === "string" && typeof value.t === "string"
      ? { p: value.p, x: value.x, t: value.t }
      : null;
  }, null);
}

function remove(key: string): void {
  guarded((store) => {
    store.removeItem(key);
  }, undefined);
}

function keys(): string[] {
  return guarded((store) => Object.keys(store).filter((key) => key.startsWith(PREFIX)), []);
}

/** Keep (or, for an empty comment, forget) what was typed on one approval. */
export function saveApprovalDraft(approvalId: string, principal: string | undefined, expiresAt: string, text: string): void {
  if (principal === undefined || principal === "") return;
  if (text === "") {
    remove(APPROVAL + approvalId);
    return;
  }
  guarded((store) => {
    store.setItem(APPROVAL + approvalId, JSON.stringify({ p: principal, x: expiresAt, t: text.slice(0, DRAFT_LIMIT) }));
  }, undefined);
}

/**
 * The comment kept for one approval, only for the person who typed it and only before the
 * approval's deadline on the server's clock; anything else is removed and nothing restored.
 */
export function restoreApprovalDraft(approvalId: string, principal: string | undefined, nowMs: number): string | null {
  const key = APPROVAL + approvalId;
  const stored = read(key);
  if (stored === null) return null;
  if (principal === undefined || stored.p !== principal || !(nowMs < Date.parse(stored.x))) {
    remove(key);
    return null;
  }
  return stored.t;
}

/** Forget one approval's comment: decided, ended, or refused as secret-shaped. */
export function removeApprovalDraft(approvalId: string): void {
  remove(APPROVAL + approvalId);
}

/** Refusals after which the approval can never take this comment. */
const ENDED = ["APPROVAL_EXPIRED", "ALREADY_DECIDED", "NOT_FOUND", "CONFLICT"];

/**
 * What a decision's answer means for its kept comment: accepted (no `error`) or refused for good,
 * it is forgotten; refused because the kernel found the comment secret-shaped (`INVALID_BODY`
 * naming `comment`), it is forgotten too, and the answer is true so the page keeps nothing more
 * for that approval until the field is emptied. Any other refusal keeps it.
 */
export function settleApprovalDraft(approvalId: string, error?: unknown): boolean {
  const { code, fields } = (typeof error === "object" && error !== null ? error : {}) as { code?: unknown; fields?: unknown };
  const secret = code === "INVALID_BODY" && Array.isArray(fields) && fields.includes("comment");
  if (error === undefined || secret || ENDED.includes(String(code))) removeApprovalDraft(approvalId);
  return secret;
}

// The policy document's write that is waiting for typing to pause, and its timer.
let held: (() => void) | null = null;
let timer: ReturnType<typeof setTimeout> | undefined;

/** Write any held write now: before a sign-in, a reload for the second step, or the tab going. */
export function flushDrafts(): void {
  if (timer !== undefined) clearTimeout(timer);
  timer = undefined;
  const write = held;
  held = null;
  write?.();
}

function writePolicy(principal: string, text: string): void {
  if (text === "" || new TextEncoder().encode(text).length > POLICY_LIMIT) {
    remove(POLICY);
    return;
  }
  const expires = new Date(serverNow() + POLICY_LIFE_MS).toISOString();
  guarded((store) => {
    store.setItem(POLICY, JSON.stringify({ p: principal, x: expires, t: text }));
  }, undefined);
}

/** Keep (or, for an empty one, forget) the new policy document, once typing pauses. */
export function savePolicyDraft(principal: string | undefined, text: string): void {
  if (principal === undefined || principal === "") return;
  if (timer !== undefined) clearTimeout(timer);
  held = () => {
    writePolicy(principal, text);
  };
  timer = setTimeout(flushDrafts, POLICY_DEBOUNCE_MS);
}

/** The kept policy document, only for the person who typed it and only within thirty minutes
 * of its last write on the server's clock; anything else is removed and nothing restored. */
export function restorePolicyDraft(principal: string | undefined, nowMs: number): string | null {
  const stored = read(POLICY);
  if (stored === null) return null;
  if (principal === undefined || stored.p !== principal || !(nowMs < Date.parse(stored.x))) {
    remove(POLICY);
    return null;
  }
  return stored.t;
}

/** Forget the kept policy document and any write still held for it. */
export function removePolicyDraft(): void {
  if (timer !== undefined) clearTimeout(timer);
  timer = undefined;
  held = null;
  remove(POLICY);
}

/**
 * The new policy document's text, kept in this tab across signing in again: restored once for
 * the same person, written as it is typed, forgotten when the bundle is created (`created`) and
 * when a refusal names the document (`refused`), after which nothing is kept again until the
 * field is emptied. `restored` is true once a kept document came back, for the page to say so.
 */
export function usePolicyDraft(principal: string | undefined): {
  text: string;
  set: (text: string) => void;
  created: () => void;
  refused: (error: unknown) => void;
  restored: boolean;
} {
  // Read once, when the form first renders: the person is known by then, since nothing renders
  // under the session provider before the session view arrives.
  const [kept] = useState(() => restorePolicyDraft(principal, serverNow()));
  const [text, setText] = useState(kept ?? "");
  const stopped = useRef(false);
  const restored = kept !== null;
  return {
    text,
    set: (next) => {
      setText(next);
      if (next === "") stopped.current = false;
      if (!stopped.current) savePolicyDraft(principal, next);
    },
    created: () => {
      removePolicyDraft();
      setText("");
    },
    refused: (error) => {
      const { code, fields } = (typeof error === "object" && error !== null ? error : {}) as { code?: unknown; fields?: unknown };
      const named = Array.isArray(fields) && fields.some((field) => field === "document" || String(field).startsWith("document."));
      if (code === "INVALID_BODY" && named) {
        removePolicyDraft();
        stopped.current = true;
      }
    },
    restored,
  };
}

/** Forget every draft in this tab, on signing out. */
export function clearDrafts(): void {
  removePolicyDraft();
  keys().forEach(remove);
}

/** Forget every draft whose subject has already ended, by this device's clock. */
export function sweepDrafts(nowMs: number = Date.now()): void {
  for (const key of keys()) {
    const stored = read(key);
    if (stored === null || !(nowMs < Date.parse(stored.x))) remove(key);
  }
}

/** Whether this tab's storage takes a write, asked once when the store loads. */
function probe(): boolean {
  return guarded((store) => {
    const key = `${PREFIX}probe`;
    store.setItem(key, "1");
    store.removeItem(key);
    return true;
  }, false);
}

sweepDrafts();
noteStorage(probe());
// Signing in again, and a tab that is closed or navigated away, still write what was held back.
window.addEventListener(FLUSH_DRAFTS, flushDrafts);
window.addEventListener("pagehide", flushDrafts);
