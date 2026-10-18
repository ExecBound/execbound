// SPDX-License-Identifier: AGPL-3.0-only
// The figures across the top: today in large numerals, the last fifteen minutes beneath in
// smaller type (#280). The server counted every one of them, from the viewer's midnight in the
// zone they chose (#678), so a paused tab sees what the server saw.

import { useEffect, useState } from "react";

import type { BoardCounters as Counters, BoardView } from "../../api/types.gen";
import { localMidnight } from "../../lib/days";
import { type TimeZoneChoice, useTimeZone, zoneName } from "../../lib/time";
import { Time } from "../ui/Time";
import { periodLabel } from "./search";

interface Figure {
  label: string;
  value: number;
}

/**
 * What one period shows, in reading order.
 *
 * A figure the period does not count is left out rather than drawn as zero: limit refusals and
 * requests refused before a decision are read from the window's own rows and do not exist in the
 * day's tally, and "0 refused before a decision today" would be a claim nobody checked.
 */
export function figures(counters: Counters): Figure[] {
  const all: { label: string; value: number | null | undefined }[] = [
    { label: "requests", value: counters.requests },
    { label: "allowed", value: counters.allowed },
    { label: "denied", value: counters.denied },
    { label: "by a limit", value: counters.limited },
    { label: "held for a person", value: counters.held },
    // Counted by the server's clock (#678), and said only when there is one: a lapse is not
    // held, and nobody can decide it any more.
    { label: "lapsed before a decision", value: (counters.lapsed ?? 0) > 0 ? counters.lapsed : null },
    { label: "executed", value: counters.executed },
    { label: "observed only", value: counters.observed },
    { label: "refused before a decision", value: counters.refused },
    { label: "unsettled", value: counters.unsettled },
  ];
  return all.flatMap((figure) =>
    figure.value === null || figure.value === undefined
      ? []
      : [{ label: figure.label, value: figure.value }],
  );
}

/** The day the large figures count: the viewer's, from midnight in the zone they chose. */
export function todayName(choice: TimeZoneChoice): string {
  if (choice === "utc") return "Today (UTC)";
  return `Today, since 00:00 ${zoneName(choice, localMidnight(choice))}`;
}

export function BoardCounters({ view, live }: { view: BoardView; live: boolean }) {
  const [choice] = useTimeZone();
  return (
    <div className="board-counters">
      <Period name={todayName(choice)} counters={view.today} className="board-today" />
      <Period name={periodLabel(view.window_seconds)} counters={view.window} className="board-window" />
      <p className="board-note">
        <LastRequest view={view} live={live} /> Limit refusals and requests refused before a
        decision are counted for the window only.
      </p>
    </div>
  );
}

function Period({
  name,
  counters,
  className,
}: {
  name: string;
  counters: Counters;
  className: string;
}) {
  return (
    <dl className={className}>
      <div className="board-period">
        <dt className="sr-only">Period</dt>
        <dd>{name}</dd>
      </div>
      {figures(counters).map((figure) => (
        <div key={figure.label}>
          <dt>{figure.label}</dt>
          <dd className="mono">{figure.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * "Last request N seconds ago", ageing where the board is still.
 *
 * The number is the server's; only the seconds since it arrived are added here, measured as
 * local elapsed time rather than from an absolute clock, so a viewer whose machine disagrees
 * with the server about the date still sees the right answer. The server-rendered board keeps
 * this honest by reloading every five seconds; a stream that stays silent while nothing changes
 * would otherwise leave "3 seconds ago" on the wall all afternoon. A paused board does not tick,
 * because a paused board is a picture of the moment it was paused.
 */
export function LastRequest({ view, live }: { view: BoardView; live: boolean }) {
  const seconds = view.last_request_seconds;
  const observed = view.observed_at;
  // The anchor travels with the tick, so a new snapshot resets the count by being a different
  // anchor rather than by an effect writing state; the interval returns the current object
  // unchanged when the whole second has not turned, so an idle board re-renders once a second at
  // most and a still one not at all.
  const [tick, setTick] = useState({ at: observed, extra: 0 });
  useEffect(() => {
    if (!live || seconds === null) return undefined;
    const from = performance.now();
    const timer = window.setInterval(() => {
      const passed = Math.floor((performance.now() - from) / 1000);
      setTick((current) =>
        current.at === observed && current.extra === passed
          ? current
          : { at: observed, extra: passed },
      );
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [live, seconds, observed]);
  if (seconds === null) return <>No recorded request in your current view.</>;
  const total = seconds + (tick.at === observed ? tick.extra : 0);
  return (
    <>
      Last request {elapsed(total)} ago.
      {view.last_request_at ? (
        <> <Time at={view.last_request_at} precision="second" />.</>
      ) : null}
    </>
  );
}

function elapsed(seconds: number): string {
  const divisor = seconds >= 86400 ? 86400 : seconds >= 3600 ? 3600 : seconds >= 60 ? 60 : 1;
  const unit = divisor === 86400 ? "day" : divisor === 3600 ? "hour" : divisor === 60 ? "minute" : "second";
  const value = Math.floor(seconds / divisor);
  return `${String(value)} ${unit}${value === 1 ? "" : "s"}`;
}
