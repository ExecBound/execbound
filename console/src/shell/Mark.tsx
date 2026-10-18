// SPDX-License-Identifier: AGPL-3.0-only
// The mark keeps its shape; its bar takes the accent (#333). The same three paths
// as the pages' base.html, with the bar's colour read from the tokens rather than written.

export function Mark({ size = 24 }: { size?: number }) {
  return (
    <svg
      className="mark"
      width={size}
      height={size}
      viewBox="0 0 64 64"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M 42 8 H 10 V 56 H 42"
        fill="none"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M 54 8 V 22 M 54 42 V 56"
        fill="none"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
      />
      <path className="mark-bar" d="M 40 32 H 62" fill="none" strokeWidth="5" strokeLinecap="round" />
    </svg>
  );
}
