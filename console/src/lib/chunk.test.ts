// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it, vi } from "vitest";

import { isChunkLoadError, recoverChunk } from "./chunk";

function storage(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial));
  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    store,
  };
}

describe("a route chunk that fails to load", () => {
  it("is recognised by the browser's own words", () => {
    expect(isChunkLoadError(new TypeError("Failed to fetch dynamically imported module: x.js"))).toBe(true);
    expect(isChunkLoadError(new TypeError("Importing a module script failed."))).toBe(true);
    expect(isChunkLoadError(new Error("Cannot read properties of undefined"))).toBe(false);
  });

  it("reloads the page once", () => {
    const reload = vi.fn();
    const store = storage();
    const error = new TypeError("Failed to fetch dynamically imported module: y.js");
    expect(recoverChunk(error, store, reload, () => 1_000_000)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(recoverChunk(error, store, reload, () => 1_010_000)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("reloads again once a minute has passed, and never for another error", () => {
    const reload = vi.fn();
    const store = storage({ "eb.chunk-reload": "1000" });
    expect(recoverChunk(new TypeError("Loading chunk 3 failed"), store, reload, () => 100_000)).toBe(true);
    expect(recoverChunk(new Error("boom"), store, reload, () => 200_000)).toBe(false);
    expect(recoverChunk(new TypeError("Loading chunk 3 failed"), null, reload, () => 300_000)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
