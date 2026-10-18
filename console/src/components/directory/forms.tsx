// SPDX-License-Identifier: AGPL-3.0-only
import { useId, type ReactNode } from "react";

import { explain } from "./errors";

/** A labelled control; the label wraps the control so the name is implicit and exact. */
export function Field({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <label className={className === undefined ? "field" : `field ${className}`}>
      <span className="field-label">{label}</span>
      {children}
      {hint !== undefined ? <small>{hint}</small> : null}
    </label>
  );
}

/** A refusal, explained in one sentence and announced. Nothing when there is none. `explain`
 * replaces the shared sentence for a caller whose context gives a code a narrower meaning. */
export function Problem({
  error,
  explain: sentence = explain,
}: {
  error: unknown;
  explain?: (error: unknown) => string;
}) {
  if (error === null || error === undefined) return null;
  return (
    <p className="problem" role="alert">
      {sentence(error)}
    </p>
  );
}

export type Lifetime = "1" | "8" | "24" | "168" | "720" | "2160";

/** The lifetimes a console-issued credential can have, as the pages offer them. */
export const LIFETIMES: readonly [Lifetime, string][] = [
  ["1", "1 hour"],
  ["8", "8 hours"],
  ["24", "1 day"],
  ["168", "7 days"],
  ["720", "30 days"],
  ["2160", "90 days"],
];

export function isLifetime(value: string): value is Lifetime {
  return LIFETIMES.some(([hours]) => hours === value);
}

/** An API key's lifetime: the credential lifetimes, or `never` (0057), which only an agent's
 * key may have, so it is offered nowhere a person's credential or code is issued. */
export type KeyLifetime = Lifetime | "never";

export const KEY_LIFETIMES: readonly [KeyLifetime, string][] = [...LIFETIMES, ["never", "Never"]];

/** What an agent key form says while no lifetime is chosen: an integration usually needs a long
 * one, and a key is rotated before it expires (#678). */
export const LIFETIME_HINT =
  "A Tines story or another long-running integration usually needs 30 or 90 days. Rotate the key before it expires.";

/** The lifetime of an API key, with what choosing Never means said before it is issued. `note`
 * overrides the default sentence for a caller whose secret is not an agent's key, such as an
 * administrator's personal access token. An agent key form starts at `""`: nothing is chosen
 * for the person, the select reads "Choose a lifetime" with the hint under it, and the form
 * keeps its submit control disabled until a lifetime is picked. */
export function KeyLifetimeSelect({
  value,
  onChange,
  label = "Lifetime",
  note = "A key that never expires stays valid until you revoke it. Revoke it when the agent is retired or the key may have been exposed.",
}: {
  value: KeyLifetime | "";
  onChange: (next: KeyLifetime) => void;
  label?: string;
  note?: string;
}) {
  const hintId = useId();
  return (
    <>
      <Field label={label}>
        <select
          value={value}
          aria-describedby={value === "" ? hintId : undefined}
          onChange={(event) => {
            const next = KEY_LIFETIMES.find(([option]) => option === event.target.value);
            if (next !== undefined) onChange(next[0]);
          }}
        >
          {value === "" ? (
            <option value="" disabled>
              Choose a lifetime
            </option>
          ) : null}
          {KEY_LIFETIMES.map(([option, text]) => (
            <option key={option} value={option}>
              {text}
            </option>
          ))}
        </select>
      </Field>
      {value === "" ? (
        <p className="note" id={hintId}>
          {LIFETIME_HINT}
        </p>
      ) : null}
      {value === "never" ? <p className="note">{note}</p> : null}
    </>
  );
}

/** What a set-password code may last: the store bounds one to between an hour and fourteen
 * days, so the longer credential lifetimes are not offered rather than refused after a click. */
export const CODE_LIFETIMES: readonly [Lifetime, string][] = LIFETIMES.slice(0, 4);

export function LifetimeSelect({
  value,
  onChange,
  label = "Lifetime",
  id,
  options = LIFETIMES,
}: {
  value: Lifetime;
  onChange: (next: Lifetime) => void;
  label?: string;
  id?: string;
  options?: readonly [Lifetime, string][];
}) {
  return (
    <Field label={label}>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          if (isLifetime(event.target.value)) onChange(event.target.value);
        }}
      >
        {options.map(([hours, text]) => (
          <option key={hours} value={hours}>
            {text}
          </option>
        ))}
      </select>
    </Field>
  );
}
