// SPDX-License-Identifier: AGPL-3.0-only
import { describedBy, Field } from "../ui/Field";

/** The required reason every tenant change records in the audit chain. */
export function ReasonField({
  id,
  label,
  value,
  onChange,
  error,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  error?: string;
}) {
  return (
    <Field id={id} label={label} hint="Required, up to 500 characters; recorded with the change." error={error}>
      <textarea
        id={id}
        name="reason"
        rows={2}
        maxLength={500}
        required
        value={value}
        aria-describedby={describedBy(id)}
        aria-invalid={error !== undefined ? true : undefined}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </Field>
  );
}
