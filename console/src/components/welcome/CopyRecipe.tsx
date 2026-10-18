// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { Button } from "../ui/Button";

/** Copy only public configuration. Secrets remain in the separate show-once control. */
export function CopyRecipe({ label, text }: { label: string; text: string }) {
  const [message, setMessage] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setMessage("Configuration copied.");
    } catch {
      setMessage("Select the configuration above and copy it manually.");
    }
  }
  return (
    <div className="stack">
      <pre className="recipe" tabIndex={0} role="region" aria-label={label}>{text}</pre>
      <div>
        <Button onClick={() => { void copy(); }}>Copy configuration</Button>
        <span className="muted" role="status"> {message}</span>
      </div>
    </div>
  );
}
