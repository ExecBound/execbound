// SPDX-License-Identifier: AGPL-3.0-only
// Which pages keep what a person types across signing in again (#678), asked without touching
// storage. An element holding a field whose text the draft store keeps carries the
// `data-eb-kept` attribute (`KEPT_FIELD`); the notice before a session's end asks
// `useKeptFieldMounted()` whether it may say "What you have typed on this page is kept", which it
// says only while such an element is on the page and storage answered the draft store's own probe.
//
// A marker in the page rather than a registry the fields import keeps this module, and the store,
// out of a cold approval link's first load: the notice is a chunk of its own that loads after the
// page settles, and the store loads only when there is something to keep. This module never reads
// or writes storage and never imports the store, so the notice stays off the store's allowlist.

import { useSyncExternalStore } from "react";

/** The attribute that marks an element holding a keeping field. Written as a literal on each
 * field, so a page's own chunk need not import this module to carry it. */
export const KEPT_FIELD = "data-eb-kept";
/** The event `client-config.ts` sends before it leaves the page for sign-in, so the store writes
 * whatever it is still holding back. A name rather than an import keeps the client off the
 * store's allowlist; the store listens for it once it loads. */
export const FLUSH_DRAFTS = "eb:flush-drafts";

// Unknown until the store loads and probes storage; until then nothing is said to be kept.
let storage = false;
const listeners = new Set<() => void>();

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // A field mounts and unmounts as the page changes; the notice is on screen for two minutes at
  // most, so watching the page for that long is cheap.
  const observer = new MutationObserver(listener);
  observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: [KEPT_FIELD] });
  return () => {
    listeners.delete(listener);
    observer.disconnect();
  };
}

/** Whether a keeping field is on this page and storage works, so what is typed is kept. */
export function useKeptFieldMounted(): boolean {
  return useSyncExternalStore(subscribe, () => storage && document.querySelector(`[${KEPT_FIELD}]`) !== null);
}

/** The draft store's probe result, set once when it loads. */
export function noteStorage(works: boolean): void {
  storage = works;
  for (const listener of listeners) listener();
}
