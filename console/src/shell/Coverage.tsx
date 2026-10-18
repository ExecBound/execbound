// SPDX-License-Identifier: AGPL-3.0-only
import type { Mode } from "../lib/session";

/** What the enforcement mode covers, and what it does not, under the mode pill. */
export default function Coverage({ mode }: { mode: Mode }) {
  return (
    <div className="coverage-popover">
      <strong>Protection coverage</strong>
      <p>
        {mode === "ENFORCE"
          ? "Controls apply to participating requests routed through ExecBound. Individual policy mappings can still be observe-only or use an external executor."
          : mode === "OBSERVE"
            ? "Requests are evaluated and recorded. ExecBound does not dispatch them in this mode."
            : "The enforcement mode has not been loaded."}
      </p>
      <p>Calls using a separate provider credential can bypass these controls. Monitoring supplies visibility, not execution authority.</p>
    </div>
  );
}
