// SPDX-License-Identifier: AGPL-3.0-only
// Appearance: System, Light or Dark, chosen per browser like the sidebar rail and the table
// density (#333). Those two live in localStorage, because nothing outside the bundle needs them.
// This one cannot: the document carries no inline script and paints a plain frame from the tokens
// before the bundle runs, so a scheme the bundle applied would always arrive one paint late, as a
// flash of the other scheme. The server applies it instead, from a cookie, and writes
// `data-eb-scheme` into the document it serves; what is left here is writing that cookie when the
// choice changes and keeping the root element in step for the rest of this page's life.
//
// The cookie holds one of three words and nothing else. It is not a credential, it is read by
// one function on the server, it decides which palette paints and nothing more, and no row
// anywhere records it: the choice belongs to this browser, not to the person's account.

import { useCallback, useState } from "react";

export const APPEARANCES = ["system", "light", "dark"] as const;
export type Appearance = (typeof APPEARANCES)[number];

export const APPEARANCE_WORDS: Record<Appearance, string> = {
  system: "System",
  light: "Light",
  dark: "Dark",
};

export const APPEARANCE_LEAD: Record<Appearance, string> = {
  system: "Follows the setting of the machine you are on, and changes with it.",
  light: "Always the light scheme on this browser, whatever the device is set to.",
  dark: "Always the dark scheme on this browser, whatever the device is set to.",
};

// A year. A preference nobody has touched for that long is worth asking the device about
// again, and a cookie that never expires is one more thing that outlives its reason.
const YEAR = 60 * 60 * 24 * 365;

/**
 * The cookie's name, which is the server's `HumanConfig.cookie("appearance")`.
 *
 * The `__Host-` prefix is the browser's own guarantee that a cookie was set by this exact
 * origin, over HTTPS, for the whole path and no wider host — so the server takes the prefix
 * wherever it is reached over HTTPS, and this has to agree with it or a deployment would
 * write one name and read another. `tests/test_console_serving.py` holds the two equal.
 */
export function cookieName(protocol: string = window.location.protocol): string {
  return (protocol === "https:" ? "__Host-" : "") + "eb_appearance";
}

export function readAppearance(): Appearance {
  const name = cookieName();
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      const value = rest.join("=");
      // Anything else — a word from another version, a value somebody typed into their own
      // browser — is System, exactly as the server reads it.
      return value === "light" || value === "dark" ? value : "system";
    }
  }
  return "system";
}

function write(choice: Appearance): void {
  const name = cookieName();
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  // SameSite=Lax, not Strict: this is a preference, so a page arrived at from somewhere else
  // should still paint in the scheme the person chose.
  const age = choice === "system" ? "0" : String(YEAR);
  const value = choice === "system" ? "" : choice;
  document.cookie = `${name}=${value}; Path=/; Max-Age=${age}; SameSite=Lax${secure}`;
}

function apply(choice: Appearance): void {
  const root = document.documentElement;
  if (choice === "system") {
    root.removeAttribute("data-eb-scheme");
  } else {
    // A plain attribute, never a script sink: `trusted-types 'none'` governs the sinks that
    // can run code, and this is not one of them.
    root.setAttribute("data-eb-scheme", choice);
  }
}

/** The chosen appearance and a way to change it, remembered for this browser. */
export function useAppearance(): [Appearance, (choice: Appearance) => void] {
  const [appearance, setAppearance] = useState<Appearance>(readAppearance);
  const choose = useCallback((choice: Appearance) => {
    write(choice);
    // The server will render the attribute on the next document it serves; until then this
    // page has to move itself, or the choice would only show after a reload.
    apply(choice);
    setAppearance(choice);
  }, []);
  return [appearance, choose];
}
