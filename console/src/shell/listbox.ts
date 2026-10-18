// SPDX-License-Identifier: AGPL-3.0-only
// What the space switcher's and the workspace menu's popovers share (#678): a press outside
// closes, Escape closes, Tab stays inside, and the arrow keys move between the options.

import { useEffect, type KeyboardEvent, type RefObject } from "react";

/**
 * A press outside the popover and its trigger closes it, without taking focus back to the
 * trigger: the person is already somewhere else.
 */
export function useOutsidePress(panel: RefObject<HTMLElement | null>, onClose: () => void): void {
  useEffect(() => {
    const onPointer = (event: PointerEvent) => {
      const node = panel.current?.parentElement;
      if (node !== null && node !== undefined && !node.contains(event.target as Node)) onClose();
    };
    document.addEventListener("pointerdown", onPointer);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [panel, onClose]);
}

/** Escape closes; Tab and Shift Tab stay inside the popover until it is dismissed. */
export function trapPopoverKeys(event: KeyboardEvent, panel: RefObject<HTMLElement | null>, onClose: () => void): void {
  if (event.key === "Escape") {
    event.stopPropagation();
    onClose();
    return;
  }
  if (event.key !== "Tab") return;
  const focusable = [
    ...(panel.current?.querySelectorAll<HTMLElement>('input, button, [role="option"][tabindex="0"]') ?? []),
  ];
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first?.focus();
  } else if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last?.focus();
  }
}

/** Focus the option `step` places from `from` in its listbox, wrapping at either end. */
export function moveOption(from: HTMLElement, step: number): void {
  const items = [...(from.closest('[role="listbox"]')?.querySelectorAll<HTMLElement>('[role="option"]') ?? [])];
  const at = items.indexOf(from);
  items[(at + step + items.length) % items.length]?.focus();
}
