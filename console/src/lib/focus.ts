// SPDX-License-Identifier: AGPL-3.0-only
// Focus moves to the page heading on each change of page (#333), so a screen reader
// announces where the person arrived and the keyboard starts at the top of the work. The
// router says when a navigation has resolved and its page is in the document; the first
// resolution is the page load, where the skip link stays first.
//
// A change of the query alone (a filter chip, a range button, a page step, a tab, a drawer
// opening or closing) is not a change of page, and the focus stays where the person put it
// (WCAG 2.4.3, #678).

import { useRouter } from "@tanstack/react-router";
import { useEffect } from "react";

let held = false;
let forced = false;

/**
 * The next resolved navigation keeps the focus where it is: a list opening its detail is not a
 * change of page, and the detail takes the focus itself.
 */
export function holdFocus(): void {
  held = true;
}

/**
 * The next resolved navigation focuses the heading even if only the query changes: a dialog that
 * navigated as it closed (the palette, the navigation sheet) does not give the focus back.
 */
export function moveFocusNext(): void {
  forced = true;
}

export function focusHeading(root: ParentNode = document): boolean {
  const heading = root.querySelector<HTMLElement>("main h1");
  if (heading === null) return false;
  if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
  heading.focus();
  return true;
}

export function useFocusOnNavigation(): void {
  const router = useRouter();
  useEffect(() => {
    let last = router.state.location.pathname;
    return router.subscribe("onResolved", () => {
      const current = router.state.location.pathname;
      const move = forced || current !== last;
      forced = false;
      last = current;
      // A hold is spent on the navigation it was asked for, whether or not the path changed, so
      // a hold placed before a query-only change cannot swallow a later change of page.
      if (held) {
        held = false;
        return;
      }
      if (!move) return;
      // The page's own components commit before the router reports; the frame after that is
      // when the heading exists for certain.
      requestAnimationFrame(() => {
        focusHeading();
      });
    });
  }, [router]);
}
