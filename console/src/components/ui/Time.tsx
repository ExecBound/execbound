// SPDX-License-Identifier: AGPL-3.0-only
// An instant as the console prints it (#678): a `<time>` element with a machine-readable
// `dateTime`, the text in the zone the viewer chose, and the same instant in the other zone in
// its title. Both components subscribe to the "Show times in" setting, so a change repaints
// every time on screen. They render text only.

import { serverNow } from "../../lib/clock";
import { clock, deadline, instant, isInstant, listed, other, relative, useTimeZone } from "../../lib/time";

export interface TimeProps {
  at: string;
  /** `stamp` (the default) is the date, clock and zone; `clock` only inside a list whose
   * heading, column or caption names the zone; `listed` is the same with the date before the
   * clock for any day but today; `relative` is "in 6 h" or "2 h ago". */
  form?: "stamp" | "clock" | "listed" | "relative";
  precision?: "minute" | "second";
}

export function Time({ at, form = "stamp", precision = "minute" }: TimeProps) {
  const [choice] = useTimeZone();
  if (!isInstant(at)) return <span>{at}</span>;
  if (form === "relative") {
    return (
      <time dateTime={at} className="mono" title={`${instant(at, "second", choice)} · ${other(at, choice)}`}>
        {relative(at, serverNow())}
      </time>
    );
  }
  return (
    <time dateTime={at} className="mono" title={other(at, choice)}>
      {form === "clock" ? clock(at, choice) : form === "listed" ? listed(at, serverNow(), choice) : instant(at, precision, choice)}
    </time>
  );
}

/** "4 min left, by 13:39 EDT", or "Lapsed at 13:39 EDT", against the server's `now`. */
export function Deadline({ at, now }: { at: string; now: number }) {
  const [choice] = useTimeZone();
  if (!isInstant(at)) return <span>{at}</span>;
  return (
    <time dateTime={at} className="mono" title={other(at, choice)}>
      {deadline(at, now, choice)}
    </time>
  );
}
