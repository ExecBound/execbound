// SPDX-License-Identifier: AGPL-3.0-only
export interface Chip<T extends string> {
  value: T;
  label: string;
}

/** A row of filter chips: one pressed at a time, each a toggle button in a named group. */
export function Chips<T extends string>({
  label,
  chips,
  value,
  onChange,
}: {
  label: string;
  chips: readonly Chip<T>[];
  value: string;
  onChange: (next: T) => void;
}) {
  return (
    <div className="chips" role="group" aria-label={label}>
      {chips.map((chip) => (
        <button
          key={chip.value}
          type="button"
          className={chip.value === value ? "chip chip-on" : "chip"}
          aria-pressed={chip.value === value}
          onClick={() => {
            onChange(chip.value);
          }}
        >
          {chip.label}
        </button>
      ))}
    </div>
  );
}
