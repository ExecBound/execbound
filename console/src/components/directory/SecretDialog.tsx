// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { toast } from "../../lib/toast";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { expiry, prefix, words } from "./format";

/** What one issuing mutation answered: the secret, its identifiers and, from `Govern this
 * agent`, what to do next. It lives in a component's state while this dialog is open and
 * nowhere else (#333, the show-once rule). */
export interface Shown {
  token: string;
  credential_id: string;
  principal_id: string;
  kind: string;
  expires_at: string;
  // An agent's key's counting number in its workspace (0058); absent or null for a person's.
  number?: number | null;
  next_steps?: { install: string; mcp: string };
}

/** A personal access token (design 2026-09-25), named by what its owner called it. It stands
 * for the owner and has no credential of its own to show. */
export interface ShownToken {
  kind: "TOKEN";
  token: string;
  name: string;
  expires_at: string;
}

function isToken(secret: Shown | ShownToken): secret is ShownToken {
  return secret.kind === "TOKEN";
}

/**
 * The show-once dialog. It closes on its own button only: a stray click outside or an Escape
 * would lose a secret that cannot be shown again. The token sits in a read-only field with a
 * Copy button and appears in no recipe below it.
 */
export function SecretDialog({
  secret,
  onClose,
  replaces,
}: {
  secret: Shown | ShownToken | null;
  onClose: () => void;
  /** The key a rotation replaces, as a sentence names it ("key 12"): the dialog then says
   * where the new key goes and what to revoke afterwards. */
  replaces?: string;
}) {
  const [copied, setCopied] = useState(false);
  const token = secret !== null && isToken(secret) ? secret : null;
  const shown = secret !== null && !isToken(secret) ? secret : null;
  // An agent's credential is its API key, the name the console gives it everywhere.
  const agent = shown?.kind === "AGENT";
  const noun = token !== null ? "token" : agent ? "API key" : "credential";
  const never = secret !== null && expiry(secret.expires_at) === "Never";
  const numbered = agent && shown.number !== undefined && shown.number !== null;
  const name = numbered ? `API key ${String(shown.number)}` : "";
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
      open={secret !== null}
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
          <DialogTitle className="drawer-title">Copy the {noun} now</DialogTitle>
        </div>
      </header>
      {secret !== null ? (
        <div className="dialog-body">
          {token !== null ? (
            <p>
              The token {token.name} is shown once. It is not stored and cannot be shown again; if it is lost,
              revoke it and create another.
            </p>
          ) : shown !== null ? (
            <p>
              {numbered ? (
                <>{name}</>
              ) : (
                <>
                  This {noun} for {words(shown.kind)} <span className="mono">{prefix(shown.principal_id)}</span>
                </>
              )}{" "}
              is shown once. It is not stored and cannot be shown again; if it is lost, revoke it and issue
              another.
            </p>
          ) : null}
          <label className="field">
            <span className="field-label">{token !== null ? "Token" : agent ? "API key" : "Credential"} (copy it now)</span>
            <input
              className="mono"
              type="text"
              readOnly
              value={secret.token}
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
                void copy(secret.token);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          {token !== null ? (
            <p>
              Send it on each call to the console API as <code>Authorization: Bearer &lt;token&gt;</code>.
            </p>
          ) : null}
          {agent ? (
            <p>
              The agent sends it as <code>Authorization: Bearer &lt;API key&gt;</code>, or reads it from{" "}
              <code>EXECBOUND_CREDENTIAL</code>.
            </p>
          ) : null}
          {token !== null ? (
            <p className="note">
              {never ? "It never expires." : `It expires ${expiry(token.expires_at)}.`} Anyone holding this string can
              call the console API as you {never ? "until it is revoked" : "until then"}. The audit chain records
              identifiers only.
            </p>
          ) : shown !== null ? (
            <p className="note">
              {numbered ? name : <>{agent ? "API key" : "Credential"} <span className="mono">{prefix(shown.credential_id)}</span></>}{" "}
              {never ? "never expires." : `expires ${expiry(shown.expires_at)}.`} Anyone holding this string can act as
              this {agent ? "agent" : "principal"} {never ? "until it is revoked" : "until then"}. The audit chain records
              identifiers only.
            </p>
          ) : null}
          {replaces !== undefined && shown !== null ? (
            <p>
              Next, put this key where {replaces} is used, such as the Tines story&apos;s credential, then revoke{" "}
              {replaces} on this page.
            </p>
          ) : null}
          {shown?.next_steps !== undefined ? (
            <section>
              <h3>What to do next</h3>
              <p>
                Point the agent&apos;s MCP host at this gateway with the API key above in place
                of the placeholder. No ExecBound client installation is required for MCP.
                Nothing below contains the secret.
              </p>
              <pre>{shown.next_steps.mcp}</pre>
              <details>
                <summary>Optional Python client (source checkout required)</summary>
                <pre>{shown.next_steps.install}</pre>
              </details>
              <p className="note">
                Recipes for other hosts are on this agent&apos;s page, under Connect this agent. The agent&apos;s requests count
                as this binding&apos;s verified reach from its first execution.
              </p>
            </section>
          ) : null}
        </div>
      ) : null}
      <footer className="dialog-foot">
        <DialogClose className="btn btn-primary">I have copied it</DialogClose>
      </footer>
    </DialogSurface>
  );
}
