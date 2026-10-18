// SPDX-License-Identifier: AGPL-3.0-only
import { useId } from "react";

import type { Tone } from "../ui/Badge";
import { format, stroke } from "./tones";

export interface Series {
  label: string;
  tone: Tone;
  values: number[];
}

// A label is drawn centred under its column, which would put the first one's left half
// outside the plot and cut its leading character off. A label that would cross either edge
// is anchored to that edge instead, so the text's own advance keeps it inside the viewBox
// whatever width a platform measures for it. This estimate only decides whether a label is
// near enough an edge to need that: half a label is about this many user units per character
// at the 11 px the stylesheet sets. It used to decide the position as well, and on a Linux CI
// runner "16 Wed" measured 38.52 units against the 38.4 it assumed, which cut its first
// character by a sixteenth of a unit whenever the week began on a Wednesday.
const HALF_CHAR = 3.2;

// How far inside the edge an anchored label sits. An anchor places the advance exactly, but
// a glyph's outline can overhang its advance: in Chromium at 11 px of IBM Plex Sans the most
// is a third of a unit past a start anchor ("j") and a fifth past an end anchor ("W"). One
// unit covers either three times over and is about a pixel on screen.
const EDGE_INSET = 1;

/**
 * Decisions over time by outcome: one column per label, the series stacked in order. The
 * figure carries a description a screen reader can use: the totals by outcome, where the
 * activity is and the step, rather than every empty column read out in turn
 * (#427).
 */
export function StackedBars({
  title,
  labels,
  series,
  columns,
  span,
  step,
  width = 640,
  height = 160,
}: {
  title: string;
  labels: string[];
  series: Series[];
  /** The name of every column, for the description; `labels` draws only some of them. */
  columns?: string[];
  /** How far back the chart reaches, in words ("7 days"). */
  span?: string;
  /** How wide one column is, in words ("6 hours"). */
  step?: string;
  width?: number;
  height?: number;
}) {
  const id = useId();
  const totals = labels.map((_, column) =>
    series.reduce((sum, item) => sum + (item.values[column] ?? 0), 0),
  );
  const max = Math.max(1, ...totals);
  const gap = 6;
  const bar = labels.length > 0 ? (width - gap * (labels.length - 1)) / labels.length : width;
  const plotHeight = height - 22;
  return (
    <figure className="chart" aria-labelledby={`${id}-title`} aria-describedby={`${id}-caption`}>
      <svg viewBox={`0 0 ${String(width)} ${String(height)}`} role="img" aria-labelledby={`${id}-title`}>
        <title id={`${id}-title`}>{title}</title>
        {labels.map((label, column) => {
          let y = plotHeight;
          const x = column * (bar + gap);
          const middle = x + bar / 2;
          const half = label.length * HALF_CHAR;
          let at = middle;
          let anchor: "start" | "middle" | "end" = "middle";
          if (middle - half < 0) {
            at = EDGE_INSET;
            anchor = "start";
          } else if (middle + half > width) {
            at = width - EDGE_INSET;
            anchor = "end";
          }
          return (
            <g key={column}>
              {series.map((item) => {
                const value = item.values[column] ?? 0;
                const h = (value / max) * plotHeight;
                y -= h;
                return (
                  <rect
                    key={item.label}
                    x={x}
                    y={y}
                    width={bar}
                    height={h}
                    fill={stroke(item.tone)}
                    rx={2}
                  />
                );
              })}
              <text x={at} y={height - 6} textAnchor={anchor} className="chart-label">
                {label}
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption id={`${id}-caption`} className="sr-only">
        {summarise({ title, count: totals.length, totals, series, columns, span, step })}
      </figcaption>
    </figure>
  );
}

/**
 * The chart in a sentence or three: what it holds in all, the totals by outcome, and where
 * in the range the activity is. An enumeration of every column is the right shape only when
 * most columns carry something; a week of six-hour columns almost never does.
 */
export function summarise({
  title,
  count,
  totals,
  series,
  columns,
  span,
  step,
}: {
  title: string;
  count: number;
  totals: number[];
  series: Series[];
  columns?: string[];
  span?: string;
  step?: string;
}): string {
  const over = span === undefined ? "" : ` over the last ${span}`;
  const all = totals.reduce((sum, value) => sum + value, 0);
  if (all === 0) return `${title}. Nothing${over === "" ? "" : over}.`;
  const by = series
    .map((item) => `${item.label} ${format(item.values.reduce((sum, value) => sum + value, 0))}`)
    .join(", ");
  const every = step === undefined ? "" : `, one column every ${step}`;
  const said = [`${title}. ${format(all)} in all${over}${every}: ${by}.`];
  const busy = totals.map((value, index) => ({ value, index })).filter((entry) => entry.value > 0);
  const first = busy[0];
  const last = busy[busy.length - 1];
  if (first === undefined || last === undefined) return said.join(" ");
  const name = (index: number): string => columns?.[index] ?? `column ${String(index + 1)}`;
  const peak = busy.reduce((most, entry) => (entry.value > most.value ? entry : most), first);
  if (busy.length === 1) {
    said.push(`All of it is in one of ${format(count)} columns, ${name(peak.index)}.`);
  } else {
    said.push(
      `${format(busy.length)} of ${format(count)} columns carry something, ` +
        `from ${name(first.index)} to ${name(last.index)}; ` +
        `the tallest is ${name(peak.index)} with ${format(peak.value)}.`,
    );
  }
  return said.join(" ");
}
