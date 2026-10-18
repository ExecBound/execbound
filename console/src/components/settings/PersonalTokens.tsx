// SPDX-License-Identifier: AGPL-3.0-only
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";

import {
  deleteOwnTokenMutation,
  issueTokenMutation,
  listOwnTokensOptions,
  listOwnTokensQueryKey,
  listWorkspaceTokensQueryKey,
  revokeOwnTokenMutation,
} from "../../api/@tanstack/react-query.gen";
import type { TokenRow, TokensPage } from "../../api/types.gen";
import { useServerMutation } from "../../lib/mutation";
import { useRetry } from "../../lib/retry";
import { toast } from "../../lib/toast";
import { ConfirmDialog } from "../directory/ConfirmDialog";
import { explain, refusalOf } from "../directory/errors";
import { expiry, when } from "../directory/format";
import { Field, KeyLifetimeSelect, type KeyLifetime } from "../directory/forms";
import { SecretDialog } from "../directory/SecretDialog";
import { useShowOnce } from "../directory/showOnce";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { Table, Td, Th } from "../ui/Table";
import { TryAgain } from "../ui/TryAgain";

/** What choosing Never means for a personal access token: it outlives its issuer's next
 * lifetime choice, so only a revoke or the owner losing their standing here ends it. */
const NEVER_NOTE =
  "A token that never expires keeps working until it is revoked, by you or by any administrator from Workspace settings. It also stops when you leave the workspace, stop being an administrator here, or your password is reset.";

/** What a token may not do however its owner may: the routes `token_rules.TOKEN_REFUSED`
 * names, in words. Kept to that set: nothing here a token can do, and
 * nothing it cannot do left out. */
const REFUSED = [
  "approve or deny a request",
  "settle an execution",
  "activate a policy or install the sample targets",
  "switch the workspace to observe-only",
  "lift an emergency stop",
  "reactivate an agent",
  "unarchive a space",
  "change approval rules or approvers",
  "invite people, or change people, access or sign-in",
  "revoke a key from the Credentials list (an agent's own page can)",
  "connect, re-key or revoke a monitoring connection, or mint, rotate or revoke a reporting source",
  "acknowledge several monitoring findings at once",
  "resolve a person's account request",
  "change your own account",
  "list, create, revoke or delete tokens",
  "read the browser session or switch its workspace or space",
];

/** A refused create, in a token's words. The shared DIRECTORY_REQUIRED sentence asks the person
 * to sign in through their organization; here the workspace refuses every token outright, and
 * signing in again would not change that. */
function explainIssue(error: unknown): string {
  return refusalOf(error).code === "DIRECTORY_REQUIRED"
    ? "This workspace requires organization sign-in, so it does not accept personal access tokens."
    : explain(error);
}

/**
 * An administrator's own personal access tokens (design 2026-09-25): a token calling the
 * console API as its owner, with an administrator's authority but none of the standing-only
 * refusals said below. Issued, shown once, revoked or deleted here; a workspace's whole set is
 * on Workspace settings.
 */
export function PersonalTokens() {
  const queryClient = useQueryClient();
  const tokens = useQuery(listOwnTokensOptions());
  const retry = useRetry(tokens);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [lifetime, setLifetime] = useState<KeyLifetime>("720");
  const [revoking, setRevoking] = useState<TokenRow | null>(null);
  const [deleting, setDeleting] = useState<TokenRow | null>(null);
  const table = useId();
  const create = useRef<HTMLDivElement | null>(null);
  // Set when a delete succeeds: the row, and the button that opened the dialog, are gone.
  const deleted = useRef(false);
  const issue = useShowOnce(issueTokenMutation());
  // Either card may show the same token, so a change here reads the workspace list again. A
  // success answers with this card's fresh list, which is written in place; a refusal, or a
  // create that answers no list, reads both again: a refusal's copy promises the page shows
  // what is there now.
  const refresh = (fresh?: TokensPage) => {
    if (fresh !== undefined) queryClient.setQueryData(listOwnTokensQueryKey(), fresh);
    else void queryClient.invalidateQueries({ queryKey: listOwnTokensQueryKey() });
    void queryClient.invalidateQueries({ queryKey: listWorkspaceTokensQueryKey() });
  };
  const revoke = useServerMutation({
    ...revokeOwnTokenMutation(),
    onSuccess: (fresh) => {
      refresh(fresh);
      toast("Token revoked.");
      setRevoking(null);
    },
    onError: () => {
      refresh();
    },
  });
  const remove = useServerMutation({
    ...deleteOwnTokenMutation(),
    onSuccess: (fresh) => {
      deleted.current = true;
      refresh(fresh);
      toast("Token deleted.");
      setDeleting(null);
    },
    onError: () => {
      refresh();
    },
  });
  const rows = tokens.data?.tokens ?? [];
  return (
    <Card title="Personal access tokens">
      <p>
        A token calls the console API as you, with <code>Authorization: Bearer &lt;token&gt;</code>. It can do
        what you can do as an administrator, and every audit event it causes names you and the token. It
        cannot:
      </p>
      <ul aria-label="What a token cannot do">
        {REFUSED.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      <p>
        Those need you, signed in. The console API reference, at <code>/api/console</code> on the documentation
        site, marks for each operation whether a token may call it. In a workspace with several spaces, name one
        with the <code>X-ExecBound-Space</code> header. A workspace that requires organization sign-in does not
        accept tokens.
      </p>
      {/* Only a first read that failed stands in for the list; a later one is said above the
          list it read. */}
      {retry.failure !== null ? (
        <p className="problem" role="alert">
          Your tokens could not be loaded. {explain(retry.failure)}{" "}
          <TryAgain retry={retry} />
        </p>
      ) : null}
      {tokens.data === undefined ? (
        retry.failure !== null ? null : (
          <p className="muted" role="status">
            Loading your tokens…
          </p>
        )
      ) : rows.length === 0 ? (
        <EmptyState title="No tokens yet." />
      ) : (
        <Table caption="Your personal access tokens." density="compact" id={table}>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Created</Th>
              <Th>Expires</Th>
              <Th>Last used</Th>
              <Th>State</Th>
              <Th>Action</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.token_id}>
                <Td>{row.name}</Td>
                <Td mono>{when(row.created_at)}</Td>
                <Td mono>{expiry(row.expires_at)}</Td>
                <Td mono>{row.last_used_at ? when(row.last_used_at) : "Never used"}</Td>
                <Td>
                  <Badge tone={row.state === "live" ? "allow" : "stale"}>{row.state}</Badge>
                </Td>
                <Td>
                  {row.state === "live" ? (
                    <Button
                      size="small"
                      aria-label={`Revoke ${row.name}`}
                      onClick={() => {
                        revoke.reset();
                        setRevoking(row);
                      }}
                    >
                      Revoke
                    </Button>
                  ) : (
                    <Button
                      size="small"
                      aria-label={`Delete ${row.name}`}
                      onClick={() => {
                        remove.reset();
                        deleted.current = false;
                        setDeleting(row);
                      }}
                    >
                      Delete
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <div className="row" ref={create}>
        <Button
          variant="primary"
          onClick={() => {
            issue.clear();
            setName("");
            setLifetime("720");
            setCreating(true);
          }}
        >
          Create token
        </Button>
      </div>
      <ConfirmDialog
        open={creating}
        title="Create a personal access token"
        confirm="Create"
        pending={issue.pending}
        confirmDisabled={name.trim() === ""}
        error={issue.error}
        explain={explainIssue}
        onConfirm={() => {
          void issue.issue({ body: { name: name.trim(), lifetime } }).then((done) => {
            if (done) {
              setCreating(false);
              setName("");
              refresh();
            }
          });
        }}
        onClose={() => {
          setCreating(false);
        }}
      >
        <Field label="Name">
          <input
            value={name}
            maxLength={80}
            placeholder="Coding agent on my laptop"
            onChange={(event) => {
              setName(event.target.value);
            }}
          />
        </Field>
        <KeyLifetimeSelect value={lifetime} onChange={setLifetime} note={NEVER_NOTE} />
      </ConfirmDialog>
      <SecretDialog
        secret={
          issue.secret
            ? {
                kind: "TOKEN",
                token: issue.secret.token,
                name: issue.secret.row.name,
                expires_at: issue.secret.row.expires_at,
              }
            : null
        }
        onClose={issue.close}
      />
      <ConfirmDialog
        open={revoking !== null}
        title={`Revoke ${revoking?.name ?? "this token"}?`}
        confirm="Revoke"
        danger
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => {
          if (revoking) revoke.mutate({ path: { token_id: revoking.token_id }, body: {} });
        }}
        onClose={() => {
          setRevoking(null);
        }}
      >
        <p>Anything using it stops working at its next request.</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting !== null}
        title={`Delete ${deleting?.name ?? "this token"}?`}
        confirm="Delete"
        danger
        pending={remove.isPending}
        error={remove.error}
        finalFocus={() =>
          deleted.current
            ? (document.getElementById(table)?.closest<HTMLElement>("[role=region]") ??
              create.current?.querySelector<HTMLElement>("button") ??
              true)
            : true
        }
        onConfirm={() => {
          if (deleting) remove.mutate({ path: { token_id: deleting.token_id }, body: {} });
        }}
        onClose={() => {
          setDeleting(null);
        }}
      >
        <p>It disappears from every list. The audit history keeps it.</p>
      </ConfirmDialog>
    </Card>
  );
}
