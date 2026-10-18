// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { toast } from "../../lib/toast";
import type { IssuedCode } from "../../api/types.gen";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { prefix, when } from "./format";

/**
 * The show-once dialog for a set-password code. It closes on its own button only, like the
 * credential dialog: a stray click or an Escape would lose a code that cannot be shown again.
 *
 * The code and the address are shown as two separate things on purpose. A link carrying the
 * code would put it in a browser history, a chat preview and every log between here and the
 * person, so the code goes into a form instead, which is the rule #178's claim code and
 * #241's invitation code already follow.
 */
export function CodeDialog({ code, onClose }: { code: IssuedCode | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast("Copied. It will not be shown again.");
    } catch {
      toast("Copying failed; select the text and copy it yourself.");
    }
  };
  return (
    <DialogSurface
      open={code !== null}
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
          <DialogTitle className="drawer-title">Copy the code now</DialogTitle>
        </div>
      </header>
      {code !== null ? (
        <div className="dialog-body">
          <p>
            Send this person the address below and the code, by whatever channel your organisation
            uses. The code is stored only as its digest and cannot be shown again; if it is lost,
            issue another, which revokes this one.
          </p>
          <label className="field">
            <span className="field-label">Page to open</span>
            <input
              className="mono"
              type="text"
              readOnly
              value={code.address}
              autoComplete="off"
              spellCheck={false}
              onFocus={(event) => {
                event.currentTarget.select();
              }}
            />
          </label>
          <label className="field">
            <span className="field-label">One-time code (copy it now)</span>
            <input
              className="mono"
              type="text"
              readOnly
              value={code.code}
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
                void copy(code.code);
              }}
            >
              {copied ? "Copied" : "Copy the code"}
            </Button>
          </div>
          <p className="note">
            Code <span className="mono">{prefix(code.reset_id)}</span> expires {when(code.expires_at)}.
            It works once, five wrong attempts revoke it, and setting the password ends every session
            and credential this person already had. The audit chain records identifiers only.
          </p>
        </div>
      ) : null}
      <footer className="dialog-foot">
        <DialogClose className="btn btn-primary">I have copied it</DialogClose>
      </footer>
    </DialogSurface>
  );
}
