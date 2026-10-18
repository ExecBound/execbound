// SPDX-License-Identifier: AGPL-3.0-only
// One timer for the whole page (#427).
//
// A `refetchInterval` per query gives every query a timer of its own, started when its
// component mounted, so three endpoints polled at the same cadence drift into three
// separate moments and two components watching one endpoint ask for it twice. Here every
// poller subscribes to one interval instead: each tick refetches each endpoint once,
// however many components are watching it, so a tick is one request per endpoint and the
// watchers read the one answer.
//
// The timer runs only while the tab is visible. It is cleared when the document hides and
// started again when it shows, so a tab left open behind another one asks for nothing; the
// query client's `refetchOnWindowFocus` is what brings a returning reader up to date.

import { useEffect, useRef } from "react";
import {
  useQuery,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";

/** Counts every 10 s while the tab is visible (#333). */
export const POLL_MS = 10_000;

type Poller = () => void;

const groups = new Map<string, Set<Poller>>();
let timer: ReturnType<typeof setInterval> | undefined;
let watching = false;

function visible(): boolean {
  return typeof document === "undefined" || document.visibilityState === "visible";
}

function tick(): void {
  for (const group of groups.values()) {
    // One refetch per endpoint, whoever is watching it: the rest read the same query.
    for (const poll of group) {
      poll();
      break;
    }
  }
}

function start(): void {
  if (timer !== undefined || groups.size === 0 || !visible()) return;
  timer = setInterval(tick, POLL_MS);
}

function stop(): void {
  if (timer === undefined) return;
  clearInterval(timer);
  timer = undefined;
}

function onVisibility(): void {
  if (visible()) start();
  else stop();
}

/** Subscribe one endpoint's refetch to the shared timer; the answer unsubscribes it. */
export function subscribe(key: string, poll: Poller): () => void {
  const group = groups.get(key) ?? new Set<Poller>();
  group.add(poll);
  groups.set(key, group);
  if (!watching && typeof document !== "undefined") {
    document.addEventListener("visibilitychange", onVisibility);
    watching = true;
  }
  start();
  return () => {
    group.delete(poll);
    if (group.size === 0) groups.delete(key);
    if (groups.size === 0) stop();
  };
}

/** Whether the shared timer is running; the tests read it, the pages do not. */
export function polling(): boolean {
  return timer !== undefined;
}

/**
 * `useQuery` on the shared timer instead of a timer of its own. Everything else is the
 * generated options the page passes, so a page reads its data exactly as it did.
 */
export function usePolledQuery<TQueryFnData, TError, TData, TQueryKey extends QueryKey>(
  options: UseQueryOptions<TQueryFnData, TError, TData, TQueryKey>,
): UseQueryResult<TData, TError> {
  const query = useQuery({ ...options, refetchInterval: false });
  const refetch = useRef(query.refetch);
  useEffect(() => {
    refetch.current = query.refetch;
  });
  const key = JSON.stringify(options.queryKey);
  // A query a page has switched off asks for nothing, so it joins no tick either.
  const enabled = options.enabled !== false;
  useEffect(() => {
    if (!enabled) return;
    return subscribe(key, () => {
      void refetch.current();
    });
  }, [key, enabled]);
  return query;
}
