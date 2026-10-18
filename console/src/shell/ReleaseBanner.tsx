// SPDX-License-Identifier: AGPL-3.0-only
import { useIsMutating } from "@tanstack/react-query";
import { useState } from "react";

import { dialogOpen } from "./Keyboard";

/**
 * "A new version of ExecBound is available", which loads on the next change of page; the page
 * keeps working. Reload is held while a change is being sent, and over an open dialog it asks
 * once, here, before anything typed into the dialog is lost. The shell loads this only once a
 * newer release has been noted.
 */
export default function ReleaseBanner() {
  const sending = useIsMutating() > 0;
  const [asking, setAsking] = useState(false);
  return (
    <div className="banner" role="status">
      <span>A new version of ExecBound is available. It loads when you next change page.</span>
      {sending ? <small className="muted">Reload when the change being sent has finished.</small> : null}
      <span className="row">
        <button
          type="button"
          className="btn btn-primary btn-small"
          disabled={sending}
          onClick={() => {
            if (!asking && dialogOpen()) {
              setAsking(true);
              return;
            }
            window.location.reload();
          }}
        >
          {asking ? "Reload and lose what is typed" : "Reload"}
        </button>
        {asking ? (
          <button
            type="button"
            className="btn btn-small"
            onClick={() => {
              setAsking(false);
            }}
          >
            Not now
          </button>
        ) : null}
      </span>
    </div>
  );
}
