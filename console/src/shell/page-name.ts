// SPDX-License-Identifier: AGPL-3.0-only
// A page names itself once (#678), and the top bar's breadcrumb and the document title both read
// that name. The breadcrumb may print a server's label as text; the title may not, because a tab
// title travels into browser history, window switchers and shared screens. Title words therefore
// have a type of their own that only the constructors below can produce, so a hostname, a target,
// an agent's label or a provider's display name in the title is a type error, not a review note.

import type { LinkOptions } from "@tanstack/react-router";
import { createContext, useContext, useEffect } from "react";

import type { Noun } from "../components/directory/handles";

declare const TITLE: unique symbol;
/** A word allowed in the document title: never a hostname, a target, or an agent's or provider's string. */
export type TitleWord = string & { readonly [TITLE]: true };

export interface Crumb {
  /** Rendered as text, with an ellipsis; may be a server's label. */
  label: string;
  /** Router link options built from identifiers, never from a string a server sent. */
  link: LinkOptions;
}

export interface PageName {
  /** The ancestors after the workspace crumb, each a link. */
  crumbs: readonly Crumb[];
  /** The current page's crumb, as text. */
  current: string;
  /** What the title says before the section's own label, most specific first. */
  title: readonly TitleWord[];
  /** The section's label where the path has no navigation entry of its own. */
  section?: TitleWord;
}

const word = (text: string): TitleWord => text as TitleWord;

const REF = /^EB-\d{1,12}$/;
const SHORT = /^[0-9a-f]{8}/;

/** A request reference such as EB-1042, and nothing else. */
export function titleRef(ref: unknown): TitleWord | undefined {
  return typeof ref === "string" && REF.test(ref) ? word(ref) : undefined;
}

/** "Agent 3" or "User 3" from a principal's positive whole counting number. */
export function titleNumber(of: Noun, n: unknown): TitleWord | undefined {
  return typeof n === "number" && Number.isInteger(n) && n > 0 ? word(`${of} ${String(n)}`) : undefined;
}

/** "Policy version 1a2b3c4d": the first eight characters of a hexadecimal id. */
export function titleShort(noun: "Policy version" | "Turn", id: unknown): TitleWord | undefined {
  return typeof id === "string" && SHORT.test(id) ? word(`${noun} ${id.slice(0, 8)}`) : undefined;
}

export type FixedNoun =
  | "Agent"
  | "User"
  | "Approval"
  | "Approvals"
  | "Request"
  | "Rules"
  | "Monitored agent"
  | "Answer"
  | "Not found"
  | "Could not load"
  | "What ExecBound did";

/** One of the console's own fixed words. */
export function titleNoun(noun: FixedNoun): TitleWord {
  return word(noun);
}

type Setter = (update: (previous: PageName | null) => PageName | null) => void;

export const PageNameValueContext = createContext<PageName | null>(null);
export const PageNameSetterContext = createContext<Setter>(() => undefined);

/** Declares the page's name while the page is mounted; `null` keeps the default. */
export function usePageName(name: PageName | null): void {
  const set = useContext(PageNameSetterContext);
  // The name is compared by value: a page that renders again with the same name changes nothing.
  const key = name === null ? "" : JSON.stringify(name);
  useEffect(() => {
    if (key === "") return;
    const mine = JSON.parse(key) as PageName;
    set(() => mine);
    return () => {
      set((previous) => (previous === mine ? null : previous));
    };
  }, [key, set]);
}

/** The name the current page declared, or `null` for the default. */
export function usePageNameValue(): PageName | null {
  return useContext(PageNameValueContext);
}
