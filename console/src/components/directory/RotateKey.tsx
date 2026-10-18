// SPDX-License-Identifier: AGPL-3.0-only
// Rotate key N (#678): a new API key for the same agent, issued behind the same step-up and
// space check as any other, naming the old key it replaces. The old key keeps working until it
// is revoked, so the tool that uses it can be updated first; the server marks it replaced only
// because this request names it. The new key is shown once, through `useShowOnce`, and is in
// no query, mutation record, URL or storage once its dialog closes.

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { issueAgentCredentialMutation } from "../../api/@tanstack/react-query.gen";
import { Button } from "../ui/Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { keyName } from "./format";
import { KeyLifetimeSelect, type KeyLifetime } from "./forms";
import { SecretDialog } from "./SecretDialog";
import { useShowOnce } from "./showOnce";

export interface RotatedKey {
  credential_id: string;
  number?: number | null;
}

export function RotateKey({
  principalId,
  agentName,
  replaced,
}: {
  principalId: string;
  /** The agent as the page names it, rendered as text. */
  agentName: string;
  replaced: RotatedKey;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [lifetime, setLifetime] = useState<KeyLifetime | "">("");
  const issue = useShowOnce(issueAgentCredentialMutation());
  const name = keyName(replaced.number, replaced.credential_id);
  const lower = name.toLowerCase();
  return (
    <>
      <Button
        size="small"
        onClick={() => {
          issue.clear();
          setLifetime("");
          setOpen(true);
        }}
      >
        Rotate {lower}
      </Button>
      <ConfirmDialog
        open={open}
        title={`Rotate ${lower} for ${agentName}`}
        confirm="Issue the new key"
        pending={issue.pending}
        confirmDisabled={lifetime === ""}
        error={issue.error}
        onConfirm={() => {
          if (lifetime === "") return;
          void issue
            .issue({ path: { principal_id: principalId }, body: { lifetime, replaces: replaced.credential_id } })
            .then((done) => {
              if (!done) return;
              setOpen(false);
              void queryClient.invalidateQueries({ queryKey: [{ _id: "readAgent" }] });
              void queryClient.invalidateQueries({ queryKey: [{ _id: "listCredentials" }] });
              void queryClient.invalidateQueries({ queryKey: [{ _id: "listExpiringKeys" }] });
            });
        }}
        onClose={() => {
          setOpen(false);
        }}
      >
        <p>
          This issues a new API key for {agentName}. {name} keeps working until you revoke it, so you can update the
          tool that uses it first.
        </p>
        <KeyLifetimeSelect value={lifetime} onChange={setLifetime} />
      </ConfirmDialog>
      <SecretDialog secret={issue.secret} replaces={lower} onClose={issue.close} />
    </>
  );
}
