// SPDX-License-Identifier: AGPL-3.0-only
import { useId } from "react";

import type { Tone } from "../ui/Badge";
import { format, stroke } from "./tones";

/**
 * The line in a sentence: what it holds in all, how much of the range carries anything,
 * the tallest period and where the line ends.
 *
 * It used to open "from 0 to 0", the first and last values, which over a week of
 * six-hour periods that are nearly all empty said nothing at all
 * (#427). This is the shape the
 * stacked chart's description already uses, said for a line rather than for columns.
 */
export function summariseLine(title: string, values: number[]): string {
  const all = values.reduce((sum, value) => sum + value, 0);
  const count = values.length;
  if (count === 0 || all === 0) return `${title}. Nothing.`;
  const high = Math.max(...values);
  const last = values[count - 1] ?? 0;
  const busy = values.filter((value) => value > 0).length;
  const periods = `${format(count)} ${count === 1 ? "period" : "periods"}`;
  if (busy === count) {
    return `${title}. ${format(all)} in all across ${periods}, every one of them carrying something, the tallest ${format(high)}. It ends at ${format(last)}.`;
  }
  const where =
    busy === 1
      ? `all of it in one of ${periods}`
      : `${format(busy)} of ${periods} carrying something, the tallest ${format(high)}`;
  return `${title}. ${format(all)} in all, ${where}. It ends at ${format(last)}.`;
}

/** A small line beside a figure; the caption summarises what the line holds. */
export function Sparkline({
  title,
  values,
  tone = "accent",
  width = 96,
  height = 28,
}: {
  title: string;
  values: number[];
  tone?: Tone;
  width?: number;
  height?: number;
}) {
  const id = useId();
  const low = Math.min(...values);
  const high = Math.max(...values);
  const span = high - low || 1;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((value, index) => `${String(index * step)},${String(height - 2 - ((value - low) / span) * (height - 4))}`)
    .join(" ");
  return (
    <figure className="sparkline" aria-labelledby={`${id}-title`} aria-describedby={`${id}-caption`}>
      <svg viewBox={`0 0 ${String(width)} ${String(height)}`} role="img" aria-labelledby={`${id}-title`}>
        <title id={`${id}-title`}>{title}</title>
        <polyline points={points} fill="none" stroke={stroke(tone)} strokeWidth="1.75" strokeLinejoin="round" />
      </svg>
      <figcaption id={`${id}-caption`} className="sr-only">
        {summariseLine(title, values)}
      </figcaption>
    </figure>
  );
}
