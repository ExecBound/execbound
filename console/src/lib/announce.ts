// SPDX-License-Identifier: AGPL-3.0-only
// One polite live region for the whole console (#678). A page says what changed with
// `announce(text)` rather than rendering a status region of its own, so a screen reader hears one
// voice and a message repeated on purpose is spoken again. Toasts keep their own region.

import { createElement } from "react";

let region: HTMLElement | null = null;
let frame: number | undefined;

/** Speaks `text` politely: the region is cleared, then set on the next frame. */
export function announce(text: string): void {
  const target = region;
  if (target === null) return;
  target.textContent = "";
  if (frame !== undefined) cancelAnimationFrame(frame);
  frame = requestAnimationFrame(() => {
    frame = undefined;
    target.textContent = text;
  });
}

/** The region itself, rendered once by the shell. */
export function Announcer() {
  return createElement("div", { ref: hold, "data-announcer": "", role: "status", "aria-live": "polite", className: "sr-only" });
}

function hold(node: HTMLDivElement | null): () => void {
  region = node;
  return () => {
    if (region === node) region = null;
  };
}
