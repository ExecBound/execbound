// SPDX-License-Identifier: AGPL-3.0-only
// Every build carries its release in a meta tag and every API response in a header (#333).
// When they differ the console says so and keeps working; nothing here decides
// anything, so the store is a boolean and a banner.

import { useSyncExternalStore } from "react";

export const RELEASE_HEADER = "X-ExecBound-Release";
export const RELEASE_META = "execbound-release";

let newer = false;
const listeners = new Set<() => void>();

export function builtRelease(root: ParentNode = document): string {
  return root.querySelector(`meta[name="${RELEASE_META}"]`)?.getAttribute("content") ?? "";
}

/** Compare a response's release with the built one; a difference is remembered until reload. */
export function noteRelease(headers: Headers, root: ParentNode = document): void {
  const served = headers.get(RELEASE_HEADER);
  const built = builtRelease(root);
  if (served !== null && served !== "" && built !== "" && served !== built && !newer) {
    newer = true;
    for (const listener of listeners) listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useNewerRelease(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => newer,
    () => false,
  );
}

export function forgetRelease(): void {
  newer = false;
}
