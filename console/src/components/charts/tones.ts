// SPDX-License-Identifier: AGPL-3.0-only
import type { Tone } from "../ui/Badge";

/** Every chart draws with token colours only; a tone names one (#333). */
export function stroke(tone: Tone): string {
  return `var(--eb-${tone})`;
}

export function format(value: number): string {
  return new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(value);
}

let counter = 0;
export function chartId(prefix: string): string {
  counter += 1;
  return `${prefix}-${String(counter)}`;
}
