// SPDX-License-Identifier: AGPL-3.0-only
import { useId } from "react";

import type { Tone } from "../ui/Badge";
import { stroke } from "./tones";

/** The time left on an approval as a ring: 30 px in lists, 72 px on the approval page. */
export function CountdownRing({
  remainingSeconds,
  totalSeconds,
  size = 30,
  label,
}: {
  remainingSeconds: number;
  totalSeconds: number;
  size?: number;
  label?: string;
}) {
  const id = useId();
  const fraction = totalSeconds > 0 ? Math.max(0, Math.min(1, remainingSeconds / totalSeconds)) : 0;
  const tone: Tone = fraction <= 0.25 ? "deny" : "hold";
  const width = size >= 60 ? 5 : 3;
  const radius = (size - width) / 2;
  const circumference = 2 * Math.PI * radius;
  const text = `${clock(remainingSeconds)} left`;
  return (
    // Not `ring`: that name is also a utility class of the stylesheet's framework, which drew a
    // square frame around the circle (#678).
    <span className="countdown-ring" aria-hidden={label === undefined ? undefined : "true"}>
      <svg width={size} height={size} viewBox={`0 0 ${String(size)} ${String(size)}`} role="img" aria-labelledby={`${id}-title`}>
        <title id={`${id}-title`}>{label ?? text}</title>
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--eb-line2)" strokeWidth={width} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={stroke(tone)}
          strokeWidth={width}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
          transform={`rotate(-90 ${String(size / 2)} ${String(size / 2)})`}
        />
      </svg>
    </span>
  );
}

export function clock(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return `${String(minutes)}:${rest.toString().padStart(2, "0")}`;
}
