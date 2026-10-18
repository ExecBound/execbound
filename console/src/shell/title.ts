// SPDX-License-Identifier: AGPL-3.0-only
// Every tab says which page, space and workspace it shows (#678), most specific first so a narrow
// tab strip keeps what tells tabs apart, and how many approvals wait for this person:
//
//   (2) EB-1042 · Approvals · Payments · Acme SOC · ExecBound
//
// The title is composed only of the console's own words, the workspace and space names, the
// count and the page's title words (`TitleWord`), so a hostname, a target or an agent's label
// never reaches history, a window switcher or a shared screen. The count is the pill's query on
// the page's one polling timer, which stops while the tab is hidden; a person who comes back is
// brought up to date by the query client's refetch on focus, so nothing asks while hidden.

import { useEffect, useRef } from "react";

import { useEdition } from "../edition/context";
import { announce } from "../lib/announce";
import { useSession } from "../lib/session";
import { usePending } from "./pending";
import { entryFor } from "./navigation";
import type { PageName, TitleWord } from "./page-name";

const PRODUCT = "ExecBound";
const SEPARATOR = " · ";
/** The queue's page size: a next page means at least this many. */
const PAGE = 50;
/** Arrivals within this long of each other are announced as one. */
export const QUIET_MS = 1000;

export interface TitleParts {
  count: number | undefined;
  more: boolean;
  words: readonly TitleWord[];
  section: string | undefined;
  space: string | undefined;
  workspace: string;
}

export function composeTitle({ count, more, words, section, space, workspace }: TitleParts): string {
  const parts = [...words, section, space, workspace, PRODUCT].filter(
    (part): part is string => part !== undefined && part !== "",
  );
  const waiting = count !== undefined && count > 0 ? `(${more ? `${String(PAGE)}+` : String(count)}) ` : "";
  return waiting + parts.join(SEPARATOR);
}

/** "1 approval waiting for you", "3 approvals waiting for you". */
export function waitingWords(count: number): string {
  return `${String(count)} ${count === 1 ? "approval" : "approvals"} waiting for you`;
}

/** Sets the document title for the current page, and restores the product's name on unmount. */
export function useDocumentTitle(pathname: string, name: PageName | null): void {
  const session = useSession();
  const { navigation } = useEdition();
  const pending = usePending();
  const entry = entryFor(pathname, navigation, session.role, {
    assistant: session.assistant,
    invitations: session.invitations,
    permissions: session.permissions,
  });
  const title = composeTitle({
    count: pending.count,
    more: pending.more,
    words: name?.title ?? [],
    section: name?.section ?? entry?.label,
    space: session.space?.name,
    workspace: session.tenant.name,
  });
  useEffect(() => {
    document.title = title;
  }, [title]);
  useEffect(
    () => () => {
      document.title = PRODUCT;
    },
    [],
  );
  useCountAnnouncement(pending.count, pending.at, `${session.tenant.id ?? ""}/${session.space?.id ?? ""}`);
}

/**
 * Says politely when more approvals wait than were last read, after a second of quiet so several
 * arrivals are one message. Never on the first read, never for an unchanged count, and never as
 * the count a new space or workspace starts with: after a change of `scope`, an answer read before
 * the change is ignored and the next one is a first read.
 */
export function useCountAnnouncement(count: number | undefined, at: number, scope: string): void {
  const last = useRef<{ scope: string; count: number | undefined; stale: number } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    if (last.current?.scope !== scope) {
      clearTimeout(timer.current);
      last.current = { scope, count: undefined, stale: last.current === null ? -1 : at };
    }
    const seen = last.current;
    if (count === undefined || at === seen.stale) return;
    const before = seen.count;
    seen.count = count;
    if (before === undefined || count <= before) return;
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      announce(waitingWords(count));
    }, QUIET_MS);
  }, [count, at, scope]);
  useEffect(
    () => () => {
      clearTimeout(timer.current);
    },
    [],
  );
}
