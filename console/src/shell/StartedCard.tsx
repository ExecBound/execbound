// SPDX-License-Identifier: AGPL-3.0-only
// The sidebar's Getting started card (#678): how many required setup steps this Space has done
// and which is next, read from records (`GET /setup`), never from a click. It never polls: the
// read is fresh for thirty seconds, a returning reader's focus refetches it, and every change the
// console makes successfully invalidates it (`useSetupRefresh`). Once every required step is done, or where
// this person hid it in this browser, it is the plain "Getting started" footer row.
//
// The sidebar loads this module on demand (`StartedFoot`), showing the plain row meanwhile, so
// the read stays out of the shell every page loads first, an approval link opened cold included.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";

import { readSetupOptions } from "../api/@tanstack/react-query.gen";
import { NEXT_WORDS, useSetupCardHidden } from "../components/welcome/setup";
import { useSession } from "../lib/session";
import { Icon } from "./icons";
import type { NavigationEntry } from "./navigation";
import "./started.css";

export interface SetupProgress {
  /** "3 of 5 · Next: Choose a reviewer", or null where the card is the plain row. */
  line: string | null;
  done: number;
  required: number;
}

const ROW: SetupProgress = { line: null, done: 0, required: 0 };

/** The card's words, or the plain row; `enabled` only where the footer offers Getting started. */
export function useSetupProgress(enabled: boolean): SetupProgress {
  const session = useSession();
  const hidden = useSetupCardHidden(session.tenant.id);
  const view = useQuery({ ...readSetupOptions(), staleTime: 30_000, enabled }).data;
  if (!enabled || hidden || view?.state !== "ready" || view.done >= view.required) return ROW;
  const enforcing = view.next === null && view.milestones.some((item) => item.state === "needs_enforcing");
  const next = !view.connected
    ? "Next: Connect a provider"
    : view.next !== null
      ? `Next: ${NEXT_WORDS[view.next]}`
      : enforcing
        ? "Approvals need Enforcing"
        : null;
  if (next === null) return ROW;
  return { line: `${String(view.done)} of ${String(view.required)} · ${next}`, done: view.done, required: view.required };
}

export function StartedCard({ progress, rail }: { progress: SetupProgress; rail: boolean }) {
  const percent = progress.required === 0 ? 0 : Math.round((progress.done / progress.required) * 100);
  return (
    <Link
      to="/welcome"
      className="started"
      title={rail ? `Getting started: ${String(progress.done)} of ${String(progress.required)}` : undefined}
    >
      <Icon name="started" />
      <span className="nav-label started-body">
        <strong>Getting started</strong>
        <small>{progress.line}</small>
        <span className="started-track" aria-hidden="true">
          <span className="started-fill" style={{ width: `${String(percent)}%` }} />
        </span>
      </span>
    </Link>
  );
}

/**
 * Any change the console makes successfully may complete a setup step (an API key issued or
 * revoked, an agent changed, the samples, a policy activated, an approval decided, the mode), so
 * each one reads the setup again, from this one place rather than beside every mutation. The
 * mutation cache says only that a change succeeded; nothing of its answer is read, so a key shown
 * once never passes through here. Getting started and Home share the read and follow it.
 */
export function useSetupRefresh(): void {
  const client = useQueryClient();
  useEffect(
    () =>
      client.getMutationCache().subscribe((event) => {
        if (event.type === "updated" && event.action.type === "success") {
          void client.invalidateQueries({ queryKey: [{ _id: "readSetup" }] });
        }
      }),
    [client],
  );
}

/**
 * The footer's list with Getting started in it: the card above the other rows while steps are
 * left, else an ordinary row among them. `item` renders a row exactly as the sidebar does.
 */
export default function StartedFoot({
  rail,
  entries,
  item,
}: {
  rail: boolean;
  entries: readonly NavigationEntry[];
  item: (entry: NavigationEntry) => ReactNode;
}) {
  const progress = useSetupProgress(true);
  useSetupRefresh();
  if (progress.line === null) return <ul className="nav-list">{entries.map(item)}</ul>;
  return (
    <>
      <StartedCard progress={progress} rail={rail} />
      <ul className="nav-list">{entries.filter((entry) => entry.to !== "/welcome").map(item)}</ul>
    </>
  );
}
