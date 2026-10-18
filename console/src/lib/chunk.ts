// SPDX-License-Identifier: AGPL-3.0-only
// A route chunk that fails to load, because a release replaced it, reloads the page once
// instead of showing an error (#333). Once: a reload within the last minute is
// remembered in sessionStorage, so a chunk that keeps failing reaches the error boundary
// rather than a loop.

const KEY = "eb.chunk-reload";
const WINDOW_MS = 60_000;

export function isChunkLoadError(error: unknown): boolean {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return /dynamically imported module|Importing a module script failed|ChunkLoadError|Failed to fetch|Loading chunk/i.test(
    text,
  );
}

export function recoverChunk(
  error: unknown,
  storage: Pick<Storage, "getItem" | "setItem"> | null = safeStorage(),
  reload: () => void = () => {
    window.location.reload();
  },
  now: () => number = Date.now,
): boolean {
  if (!isChunkLoadError(error) || storage === null) return false;
  try {
    const last = Number(storage.getItem(KEY) ?? "0");
    if (last > 0 && now() - last < WINDOW_MS) return false;
    storage.setItem(KEY, String(now()));
  } catch {
    return false;
  }
  reload();
  return true;
}

function safeStorage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}
