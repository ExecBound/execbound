// SPDX-License-Identifier: AGPL-3.0-only
import type { Tone } from "../ui/Badge";
import { format, stroke } from "./tones";

/** A budget meter: used of allowed, as a bar and as a sentence. */
export function Meter({
  label,
  value,
  max,
  tone,
}: {
  label: string;
  value: number;
  max: number;
  tone?: Tone;
}) {
  const fraction = max > 0 ? Math.min(1, value / max) : 0;
  const shade: Tone = tone ?? (fraction >= 1 ? "deny" : fraction >= 0.75 ? "hold" : "accent");
  return (
    <div className="meter">
      <div className="meter-row">
        <span className="meter-label">{label}</span>
        <span className="meter-value mono">
          {format(value)} of {format(max)}
        </span>
      </div>
      <div
        className="meter-track"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={value}
        aria-valuetext={`${format(value)} of ${format(max)}`}
      >
        <div className="meter-fill" style={{ width: `${String(fraction * 100)}%`, background: stroke(shade) }} />
      </div>
    </div>
  );
}
