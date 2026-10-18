// SPDX-License-Identifier: AGPL-3.0-only
// The setup's Verify step keeps checking a new connection while the person waits (#678). It is
// not a polled read: it re-sends the existing check every ten seconds, only while the caller
// says the last answer asked for it, only while the tab is visible (#427), never while a check
// is out, and for ten minutes of wall time at most. One timeout is armed after each settle.

import { useEffect, useRef, useState, useSyncExternalStore } from "react";

function subscribe(onChange: () => void): () => void {
  document.addEventListener("visibilitychange", onChange);
  return () => {
    document.removeEventListener("visibilitychange", onChange);
  };
}

const isVisible = (): boolean => document.visibilityState !== "hidden";

interface Run {
  startedAt: number;
  stopped: boolean;
  capped: boolean;
  /** Checks sent by the timer, so each one re-arms it even when its answer comes back at once. */
  ticks: number;
}

export interface Listening {
  /** Checking again on a timer now. */
  listening: boolean;
  /** Stopped because ten minutes passed while the answer still asked to wait. */
  stoppedAtCap: boolean;
  /** Begin a run at the first check; a later first check begins another. */
  start: () => void;
  stop: () => void;
}

export function useListening(
  check: () => void,
  {
    active,
    pending,
    intervalMs = 10_000,
    capMs = 600_000,
  }: { active: boolean; pending: boolean; intervalMs?: number; capMs?: number },
): Listening {
  const visible = useSyncExternalStore(subscribe, isVisible, () => true);
  const [run, setRun] = useState<Run | null>(null);
  const latest = useRef(check);
  useEffect(() => {
    latest.current = check;
  });
  const listening = active && run !== null && !run.stopped && !run.capped;
  useEffect(() => {
    if (!listening || pending || !visible) return;
    const left = run.startedAt + capMs - Date.now();
    const timer = setTimeout(
      () => {
        if (Date.now() - run.startedAt >= capMs) {
          setRun({ ...run, capped: true });
          return;
        }
        setRun({ ...run, ticks: run.ticks + 1 });
        latest.current();
      },
      Math.max(0, Math.min(intervalMs, left)),
    );
    return () => {
      clearTimeout(timer);
    };
  }, [listening, pending, visible, run, intervalMs, capMs]);
  return {
    listening,
    stoppedAtCap: active && run?.capped === true,
    start: () => {
      setRun({ startedAt: Date.now(), stopped: false, capped: false, ticks: 0 });
    },
    stop: () => {
      setRun((current) => (current === null ? null : { ...current, stopped: true }));
    },
  };
}
