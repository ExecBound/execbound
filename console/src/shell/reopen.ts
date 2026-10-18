// SPDX-License-Identifier: AGPL-3.0-only
// The palette's "Search all your spaces" switches the session to All spaces, which draws the whole
// shell again (#678). The words typed are held here, in memory only, so the shell that comes back
// opens the palette with them and the search runs again under All spaces.

let held: string | null = null;

/** Keeps `query` for the palette the next shell opens. */
export function holdPaletteQuery(query: string): void {
  held = query;
}

/** The query held for the palette, if any; reading it does not clear it. */
export function heldPaletteQuery(): string | null {
  return held;
}

/** Forgets the held query, once the palette has taken it or the switch failed. */
export function releasePaletteQuery(): void {
  held = null;
}
