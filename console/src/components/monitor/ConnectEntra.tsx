// SPDX-License-Identifier: AGPL-3.0-only
import { useState } from "react";

import { startEntraConnectMutation } from "../../api/@tanstack/react-query.gen";
import { useServerMutation } from "../../lib/mutation";
import { Button } from "../ui/Button";
import { DialogClose, DialogSurface, DialogTitle } from "../ui/dialog";
import { Field } from "../ui/Field";
import {
  archivedWords,
  connectCopy,
  ENTRA_PERMISSIONS,
  isMicrosoftSignIn,
  labelFault,
  leave,
  placementWords,
  reviewedWords,
  usePlacement,
} from "./connect";

const UNAVAILABLE = "Connecting Microsoft Entra is unavailable right now.";
const FIELDS: Record<string, string> = {
  label: "Name the connection in 1 to 96 characters, without anything that reads as a secret.",
};

/**
 * Connect Microsoft Entra, or update a connection's consent (#228, #678): what the deployment's
 * app reads, who can consent and how to withdraw, then "Continue to Microsoft". The server
 * records the attempt and answers Microsoft's sign-in address; the browser goes there only when
 * the answer is that address. Nothing is created until a directory administrator approves, and
 * what the page says on the way back is read from the server. The answer carries the attempt's
 * secret state, so it is kept by no query or mutation record. A refusal for a stale factor opens
 * the step-up through the shared mutation path, which sends the start again once.
 */
export function ConnectEntra({
  displayName,
  connectionId,
  onClose,
}: {
  /** The deployment's app as a directory administrator sees it, from the server. */
  displayName: string;
  /** The consented connection whose consent to update; absent, a new connection. */
  connectionId?: string;
  onClose: () => void;
}) {
  const updating = connectionId !== undefined;
  const [label, setLabel] = useState("Microsoft Entra");
  const [problem, setProblem] = useState<string | null>(null);
  const starting = useServerMutation({
    ...startEntraConnectMutation(),
    gcTime: 0,
    onSuccess: (answer) => {
      const address = answer.authorize_url;
      starting.reset();
      if (isMicrosoftSignIn(address)) {
        leave.to(address);
      } else {
        setProblem(UNAVAILABLE);
      }
    },
    onError: (error) => {
      setProblem(connectCopy(error, FIELDS));
      starting.reset();
    },
  });
  const fault = updating ? undefined : labelFault(label);
  const placement = usePlacement();
  const needsSpace = !updating && placement.choose;
  const archived = !updating && placement.archived;
  // A Space this administrator only reviews takes no connection from them: said before the step-up.
  const reviewed = !updating && placement.reviewed !== null;
  // Nothing is placed while where it lands is read again after the session moved.
  const ready = fault === undefined && !needsSpace && !archived && !reviewed && (updating || !placement.checking);
  const title = updating ? "Update consent" : "Connect Microsoft Entra";
  return (
    <DialogSurface
      open
      onOpenChange={(open) => {
        if (!open && !starting.isPending) onClose();
      }}
      className="dialog dialog-wide"
    >
      <header className="drawer-head">
        <DialogTitle className="drawer-title">{title}</DialogTitle>
        <DialogClose className="btn btn-ghost" disabled={starting.isPending}>
          Close
        </DialogClose>
      </header>
      <form
        noValidate
        autoComplete="off"
        onSubmit={(event) => {
          event.preventDefault();
          setProblem(null);
          if (!ready || starting.isPending) return;
          starting.mutate({ body: updating ? { connection_id: connectionId } : { label: label.trim() } });
        }}
      >
        <div className="dialog-body">
          <h3>What ExecBound reads</h3>
          <p>
            {displayName} reads your directory&apos;s agent identities, applications, directory roles and audit records with
            the Microsoft Graph application permissions {ENTRA_PERMISSIONS.join(", ")}: read-only access, and nothing that
            can write.
          </p>
          <h3>Who can approve</h3>
          <p>
            Consent is given by a Global Administrator or Privileged Role Administrator of the directory, who signs in with
            Microsoft first so ExecBound can confirm which directory it is.
          </p>
          <h3>How to withdraw</h3>
          <p>
            Revoking the connection here stops collection. To withdraw access, remove the {displayName} enterprise
            application from your directory in Microsoft Entra.
          </p>
          <p>Monitoring is visibility. It does not enforce action policy or prevent an agent from acting.</p>
          {updating ? (
            <p>Update the consent when a permission this connection had is refused. The connection and what it collected stay as they are.</p>
          ) : (
            <>
              <Field id="entra-label" label="Connection name" error={fault}>
                <input
                  id="entra-label"
                  value={label}
                  maxLength={96}
                  aria-invalid={fault !== undefined}
                  onChange={(event) => {
                    setLabel(event.target.value);
                  }}
                />
              </Field>
              <p>
                <strong>Placement:</strong> {placementWords(placement, "connection")}
              </p>
              {needsSpace ? <p role="alert">Close this and choose a Space before connecting.</p> : null}
              {archived ? <p role="alert">{archivedWords(placement, "connection")}</p> : null}
              {reviewed ? <p role="alert">{reviewedWords(placement, "connection")}</p> : null}
            </>
          )}
          <p>You will sign in with Microsoft, then approve read-only access. Nothing is created until you approve.</p>
          {problem !== null ? (
            <p role="alert" className="problem">
              {problem}
            </p>
          ) : null}
        </div>
        <footer className="dialog-foot">
          <Button type="submit" variant="primary" disabled={!ready || starting.isPending} aria-busy={starting.isPending}>
            {starting.isPending ? "Starting…" : "Continue to Microsoft"}
          </Button>
        </footer>
      </form>
    </DialogSurface>
  );
}
