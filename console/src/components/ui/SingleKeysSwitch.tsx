// SPDX-License-Identifier: AGPL-3.0-only
// The switch for the single-key shortcuts (#678), in its own module so My account can render it
// without loading the keyboard list. Both places read and write the same preference.

import { useId } from "react";

import { useSingleKeys } from "../../lib/keys";

export function SingleKeysSwitch() {
  const [on, setOn] = useSingleKeys();
  const hint = useId();
  return (
    <div className="single-keys">
      <label className="check">
        <input
          type="checkbox"
          checked={on}
          aria-describedby={hint}
          onChange={(event) => {
            setOn(event.currentTarget.checked);
          }}
        />
        Use single-key shortcuts (?, g, j and k)
      </label>
      <p id={hint} className="muted">
        Turn these off if you use speech input or press keys by accident. Ctrl K or Cmd K still opens search.
      </p>
    </div>
  );
}
