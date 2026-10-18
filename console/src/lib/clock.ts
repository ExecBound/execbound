// SPDX-License-Identifier: AGPL-3.0-only
// The server's clock, read from the Date header of every API response (#333). A
// deadline counts down from the server's expiry, so a phone whose clock is wrong still shows
// the time the server will give, and the ring reaches zero when the server refuses, not before
// or after. The header has whole-second resolution; the instant lies inside that second.

import { useEffect, useState } from "react";

let offsetMs = 0;
let known = false;

export function noteServerTime(headers: Headers, receivedAt = Date.now()): void {
  const date = headers.get("date");
  if (date === null) return;
  const server = Date.parse(date);
  if (Number.isNaN(server)) return;
  offsetMs = server + 500 - receivedAt;
  known = true;
}

/** The server's time now, in milliseconds since the epoch, as well as the last response told it. */
export function serverNow(): number {
  return Date.now() + offsetMs;
}

/** The correction in milliseconds, or null while no response has carried a date yet. */
export function clockOffset(): number | null {
  return known ? offsetMs : null;
}

export function forgetServerTime(): void {
  offsetMs = 0;
  known = false;
}

/** The server's time, ticking once a second while the tab is visible: what a countdown or a
 * deadline in words reads, so a wrong device clock never moves it. */
export function useServerNow(tickMs = 1000): number {
  const [now, setNow] = useState(serverNow);
  useEffect(() => {
    const update = () => {
      if (document.visibilityState === "visible") setNow(serverNow());
    };
    const id = setInterval(update, tickMs);
    document.addEventListener("visibilitychange", update);
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", update);
    };
  }, [tickMs]);
  return now;
}

