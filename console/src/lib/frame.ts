// SPDX-License-Identifier: AGPL-3.0-only
// The plain frame index.html paints before any script (#333) stays until the console knows who
// is signed in (#678), so a person and a screen reader get its one "Loading" line, not an unstyled
// page outside the shell. Whichever renders first removes it: the session provider once the
// session is known or could not be read, the route boundary, or the not-found page. Removing it
// twice does nothing.

export function removeFrame(): void {
  document.getElementById("frame")?.remove();
}
