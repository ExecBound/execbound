// SPDX-License-Identifier: AGPL-3.0-only
// Back to the row a drawer was opened from (#678), for the lists whose drawer lives in the
// address: Activity and Home's recent decisions. Kept apart from the shell's focus rule, so only
// the pages that close such a drawer load it.

/**
 * Focuses the element `selector` names on the next frame, but only where nothing else holds the
 * focus: a drawer closed over a list whose row re-rendered underneath it lands on that row again,
 * and where the dialog already gave the focus back to its trigger this does nothing.
 */
export function returnFocus(selector: string): void {
  requestAnimationFrame(() => {
    const active = document.activeElement;
    if (active !== null && active !== document.body) return;
    document.querySelector<HTMLElement>(selector)?.focus();
  });
}

/** The selector of a record table's row button, for `returnFocus`. */
export function recordRow(id: string): string {
  return `[data-record-id="${CSS.escape(id)}"]`;
}
