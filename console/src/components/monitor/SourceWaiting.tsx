// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { readMonitorSourceOptions } from "../../api/@tanstack/react-query.gen";
import type { MonitorSource } from "../../api/types.gen";
import { refusal } from "../../lib/refusal";
import { count } from "../../lib/when";
import { Time } from "../ui/Time";

// How often the source is read while the page is visible, and for how long at most.
const EVERY_MS = 10_000;
const AT_MOST_MS = 10 * 60_000;

function heard(row: MonitorSource | undefined): row is MonitorSource {
  return row !== undefined && (row.last_heartbeat_at !== null || row.last_event_at !== null);
}

/** A read refused because the source is not, or no longer, in a Space the reader sees. */
function gone(error: unknown): boolean {
  return error !== null && error !== undefined && refusal(error).code === "NOT_FOUND";
}

function revoked(row: MonitorSource | undefined): boolean {
  return row !== undefined && row.revoked_at !== null;
}

/** The health pass has already called the source silent: never heard from since registration. */
function silent(row: MonitorSource | undefined): boolean {
  return row?.health_state === "STALE";
}

/** A span of seconds in words: "15 minutes", "an hour", "2 hours". */
function span(seconds: number): string {
  const minutes = Math.round(seconds / 60);
  if (minutes % 60 !== 0) return count(minutes, "minute");
  return minutes === 60 ? "an hour" : count(minutes / 60, "hour");
}

/** What the card says once its ten minutes are up with no heartbeat. Where the health pass allows
 * the source longer than the card waits, twice an interval of more than five minutes, a correctly
 * built story's first heartbeat may still be due, so it says when to look again rather than what
 * to fix; once that pass has called the source silent, or where it allows no longer than the
 * card, it says what to check. */
function noHeartbeat(seconds: number | undefined, stale: boolean): string {
  if (stale || seconds === undefined || 2 * seconds * 1000 <= AT_MOST_MS) {
    return "No heartbeat yet. Check the story's HTTP Request action and its credential, then reload.";
  }
  const every = seconds === 3600 ? "every hour" : `every ${span(seconds)}`;
  return `No heartbeat yet. This source expects one ${every}, so the story's first can take that long, and this has stopped checking on its own. Reload later; if the source is marked stale, ${span(2 * seconds)} after it was added, check the story's HTTP Request action and its credential.`;
}

/**
 * Waiting for a new reporting source's first heartbeat (#678). It reads the source every ten
 * seconds while the page is visible, never while it is hidden (the query's own rule), and for at
 * most ten minutes. It says to reload because no heartbeat came only from a read made once the ten
 * minutes were up: one more when they end with the page visible, or on the reader's return when
 * they ended while it was hidden, so a story that reported meanwhile is never called silent. Once
 * stopped, it reads the source again each time the reader comes back to the page. The first
 * heartbeat or event it sees, in its own reads or in the page's read of the source (`known`),
 * flips it to reporting, with a link to what the source reports. A source the health pass has
 * called silent, which it does twice the heartbeat interval after the mint, so for every interval
 * the console offers no sooner than ten minutes after it, while the card, whose ten minutes start
 * when the token dialog closes, may still be reading, says no heartbeat came and what to check,
 * and the card goes on reading for the rest of its ten minutes, so a story set up after that
 * verdict still flips it. A source
 * revoked meanwhile, or no longer in a Space the reader sees, ends the wait with a sentence saying
 * so; a read that fails within the ten minutes says so and keeps trying, and a last read that
 * fails once they are up says this has stopped checking on its own and to reload. A source that
 * expects its heartbeat every 15 or 60 minutes, which the health pass allows twice that before
 * calling it silent, may not have sent its first by then: unless that pass has already called it
 * silent, the card then says when to look again and when it would be marked stale, never that a
 * correctly built story needs fixing.
 */
export function SourceWaiting({ sourceId, storyId, known }: { sourceId: string; storyId: string; known?: MonitorSource }) {
  // When the ten minutes ended, as the read's own clock counts it.
  const [stoppedAt, setStoppedAt] = useState<number | null>(null);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setStoppedAt(Date.now());
    }, AT_MOST_MS);
    return () => {
      window.clearTimeout(timer);
    };
  }, []);
  const read = useQuery({
    ...readMonitorSourceOptions({ path: { source_id: sourceId } }),
    refetchInterval: (query) =>
      stoppedAt !== null ||
      heard(query.state.data) ||
      revoked(query.state.data) ||
      gone(query.state.error)
        ? false
        : EVERY_MS,
    refetchIntervalInBackground: false,
    // Once stopped, the reader's return reads the source once more, whatever its age.
    refetchOnWindowFocus: stoppedAt !== null ? "always" : false,
    retry: 0,
  });
  const { refetch } = read;
  useEffect(() => {
    // The final read, now if the page is visible; a hidden page reads on its reader's return.
    if (stoppedAt !== null && document.visibilityState === "visible") void refetch();
  }, [stoppedAt, refetch]);
  const reporting = [read.data, known].find(heard);
  if (reporting === undefined && (revoked(read.data) || revoked(known))) {
    return (
      <p className="monitor-note" role="status">
        This source was revoked, so story {storyId} can no longer report through it.
      </p>
    );
  }
  if (reporting === undefined && gone(read.error)) {
    return (
      <p className="monitor-note" role="status">
        This source is not in a Space you see. Reload to see what is.
      </p>
    );
  }
  if (reporting !== undefined) {
    const first = reporting.last_heartbeat_at ?? reporting.last_event_at;
    return (
      <p className="monitor-note" role="status">
        Reporting. First {reporting.last_heartbeat_at !== null ? "heartbeat" : "event"} at <Time at={first ?? ""} />.{" "}
        <Link to="/monitor" search={{ view: "activity" }}>
          See its Activity
        </Link>
      </p>
    );
  }
  // Said from a read made once the ten minutes were up.
  const final = stoppedAt !== null && read.dataUpdatedAt >= stoppedAt;
  // The health pass, which allows a new source twice its heartbeat interval, has called it silent:
  // said beside the badge, while the card goes on reading for the rest of its ten minutes.
  const stale = silent(read.data) || silent(known);
  // That last read failed: nothing reads the source again until the reader comes back, so the
  // line never says it keeps trying.
  const unread = stoppedAt !== null && read.isError && read.errorUpdatedAt >= stoppedAt;
  return (
    <p className="monitor-note" role="status">
      {final
        ? noHeartbeat(read.data?.heartbeat_seconds ?? known?.heartbeat_seconds, stale)
        : unread
          ? "The source could not be read when the ten minutes were up, so this has stopped checking on its own and reads it again only when you come back to this tab. Reload to see whether the story is reporting."
          : read.isError
            ? "The source could not be read just now; this keeps trying."
            : stale
              ? "No heartbeat yet. Check the story's HTTP Request action and its credential; this keeps checking."
              : `Waiting for the first heartbeat from story ${storyId}…`}
    </p>
  );
}
