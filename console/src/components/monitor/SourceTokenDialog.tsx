// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import type { MintedSource } from "../../api/types.gen";
import { toast } from "../../lib/toast";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { Time } from "../ui/Time";
import { heartbeatBody, intakeHost, INTAKE_ONLY } from "./connect";
import { Snippet } from "./Snippet";

/**
 * A reporting source's token, shown once (#678): the same show-once shape as an agent's key,
 * with this token's own words. A source token authorizes intake for one story and nothing else,
 * so nothing here says its holder can act as anyone. The token sits in a read-only field with a
 * Copy button and in no line of the recipe below it. The dialog closes on its own button only:
 * a stray click outside or an Escape would lose a token that cannot be shown again.
 */
export function SourceTokenDialog({ minted, onClose }: { minted: MintedSource | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async (token: string) => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      toast("Copied. It will not be shown again.");
    } catch {
      toast("Copying failed; select the text and copy it yourself.");
    }
  };
  return (
    <DialogSurface
      open={minted !== null}
      className="dialog dialog-wide"
      onOpenChange={(next, details) => {
        if (!next && details.reason === "close-press") {
          setCopied(false);
          onClose();
        }
      }}
    >
      <header className="drawer-head">
        <div>
          <div className="drawer-eyebrow">
            <Badge tone="hold">Shown once</Badge>
          </div>
          <DialogTitle className="drawer-title">Copy the source token now</DialogTitle>
        </div>
      </header>
      {minted !== null ? (
        <div className="dialog-body">
          <p>
            The token for story <span className="mono">{minted.story_id}</span> is shown once. It is not stored and cannot be
            shown again; if it is lost, rotate the source to issue another. Rotating again stops at once any earlier token
            still within its grace.
          </p>
          <label className="field">
            <span className="field-label">Source token (copy it now)</span>
            <input
              className="mono source-token"
              type="text"
              readOnly
              value={minted.token}
              autoComplete="off"
              spellCheck={false}
              onFocus={(event) => {
                event.currentTarget.select();
              }}
            />
          </label>
          <div className="row">
            <Button
              onClick={() => {
                void copy(minted.token);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="note">{INTAKE_ONLY}</p>
          <p className="note">
            It expires <Time at={minted.expires_at} />.
          </p>
          {minted.previous_valid_until !== null ? (
            <p className="note">
              The previous token keeps reporting until <Time at={minted.previous_valid_until} />; update the story&apos;s
              credential before then. Rotating again before then stops it at once.
            </p>
          ) : null}
          <section>
            <h3>Report from the story</h3>
            <p>
              Send each event and heartbeat to <span className="mono">{minted.intake_url}</span> with an HTTP Request action.
            </p>
            <p>
              Create a Tines Text credential holding this token, restrict its domain to{" "}
              <span className="mono">{intakeHost(minted.intake_url)}</span>, and reference it as{" "}
              <code>Bearer &lt;&lt;CREDENTIAL.your_credential_name&gt;&gt;</code> in the action&apos;s Authorization header.
            </p>
            <p>
              Set the Content-Type header to <code>application/json</code> and send the body as JSON text, keeping{" "}
              <code>story_id</code> a string. A heartbeat looks like this:
            </p>
            <Snippet label="Heartbeat body" value={heartbeatBody(minted.story_id)} />
          </section>
        </div>
      ) : null}
      <footer className="dialog-foot">
        <DialogClose className="btn btn-primary">I have copied it</DialogClose>
      </footer>
    </DialogSurface>
  );
}
