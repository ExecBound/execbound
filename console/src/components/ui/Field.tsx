// SPDX-License-Identifier: AGPL-3.0-only
import type { ReactNode } from "react";

/**
 * A labelled control with an optional hint and a fault. The caller renders the control with
 * the same `id`, and `describedBy(id)` names the hint for assistive technology.
 */
export function Field({
  id,
  label,
  hint,
  error,
  children,
}: {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint !== undefined ? (
        <p className="hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
      {error !== undefined ? (
        <p className="fault" id={`${id}-fault`} role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** The `aria-describedby` value of a control whose field has a hint. */
export function describedBy(id: string): string {
  return `${id}-hint`;
}
