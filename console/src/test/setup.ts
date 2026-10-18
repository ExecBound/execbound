// SPDX-License-Identifier: AGPL-3.0-only
import "@testing-library/jest-dom/vitest";

import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest runs without globals, so Testing Library does not register its own cleanup.
afterEach(() => {
  cleanup();
});

// How long a `findBy` or `waitFor` waits before failing. Testing Library's default is one
// second, which assumes the test has a machine to itself. On a loaded machine, such as a busy
// CI runner, the first render in a file, which loads its route's modules, can take longer than
// that, and tests fail with nothing wrong. A wait that succeeds returns the moment the element
// appears, so the longer limit costs nothing when the machine is quiet; it only delays the
// report of a wait that was going to fail anyway.
configure({ asyncUtilTimeout: 5000 });

// jsdom has no ResizeObserver; cmdk and Base UI observe sizes they never need in a test.
class QuietResizeObserver {
  observe(): void {
    // Nothing in a test resizes.
  }
  unobserve(): void {
    // Nothing was observed.
  }
  disconnect(): void {
    // Nothing to disconnect.
  }
}
if (typeof globalThis.ResizeObserver === "undefined") {
  Object.defineProperty(globalThis, "ResizeObserver", { value: QuietResizeObserver, writable: true });
}
if (typeof Element.prototype.scrollIntoView !== "function") {
  Element.prototype.scrollIntoView = () => undefined;
}
